"""
pipeline.py — Main orchestration pipeline.
Processes all 518 deletion requests end-to-end.
"""
import csv
import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from .config import (
    DELETION_REQUESTS_CSV, USER_IDENTITIES_CSV, USER_AUDIT_LOG_CSV,
    SYSTEM_ACTIVITY_CSV, DELETION_RULES_CSV, EVIDENCE_FILES_CSV,
    DATASET_DIR, EVIDENCE_DIR, GEMINI_API_KEY, GEMINI_MODEL, ENABLE_LLM,
    OUTPUT_PATH,
)
from .identity import IdentityResolver, IdentityResolution, parse_dt
from .policy import PolicyEngine, PolicyDecision
from .evidence import (
    EvidenceFile, EvidenceFinding, extract_evidence, load_evidence_manifest,
    _system_from_resource,
)
from .activity import ActivityIndex, DataFlowRisk
from .intent import IntentClassifier
from .planner import Step, build_steps, steps_to_json, validate_steps, _sort_steps

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  TOKEN / COST TRACKER
# ═══════════════════════════════════════════════════════════════════════════════

class UsageTracker:
    def __init__(self):
        self.calls: List[dict] = []

    def record(self, model: str, purpose: str, in_tokens: int, out_tokens: int):
        cost = self._estimate_cost(model, in_tokens, out_tokens)
        self.calls.append({
            'model': model, 'purpose': purpose,
            'in_tokens': in_tokens, 'out_tokens': out_tokens, 'cost': cost,
        })

    def _estimate_cost(self, model: str, inp: int, out: int) -> float:
        # Gemini 1.5 Flash pricing: $0.075 / 1M input, $0.30 / 1M output
        if 'flash' in model.lower():
            return (inp * 0.075 + out * 0.30) / 1_000_000
        # Gemini 1.5 Pro: $1.25 / 1M input, $5.00 / 1M output
        return (inp * 1.25 + out * 5.00) / 1_000_000

    @property
    def total_tokens(self) -> int:
        return sum(c['in_tokens'] + c['out_tokens'] for c in self.calls)

    @property
    def total_cost(self) -> float:
        return sum(c['cost'] for c in self.calls)

    def summary(self) -> str:
        lines = ["## LLM Usage\n",
                 f"Total calls: {len(self.calls)}",
                 f"Total tokens: {self.total_tokens:,}",
                 f"Total cost: ${self.total_cost:.4f}\n"]
        by_model = defaultdict(lambda: {'calls': 0, 'in': 0, 'out': 0, 'cost': 0.0})
        for c in self.calls:
            m = by_model[c['model']]
            m['calls'] += 1
            m['in'] += c['in_tokens']
            m['out'] += c['out_tokens']
            m['cost'] += c['cost']
        for model, m in by_model.items():
            lines.append(f"  {model}: {m['calls']} calls, {m['in']+m['out']:,} tokens, ${m['cost']:.4f}")
        return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
#  TEMPORAL STATE RECONSTRUCTOR
# ═══════════════════════════════════════════════════════════════════════════════

def _reconstruct_state(
    findings: List[EvidenceFinding],
    case_activities,
    audit_at: datetime,
) -> Dict[str, Tuple[str, str]]:
    """
    For each resource_id found in evidence, determine its state at audit_at.
    Returns: Dict[resource_id → (state, evidence_id)]

    Priority:
    1. Direct snapshot (SQL/JSON) at or before audit_at — most authoritative
    2. Log readback (state explicitly observed)
    3. Activity event (claimed result)

    Conservative rule: if ANY evidence shows PRESENT after the last DELETE_RECORD claim → PRESENT
    """
    SOURCE_PRI = {'sql': 4, 'json': 3, 'txt': 3, 'log': 2, 'activity': 1}

    # Collect all observations per resource
    obs: Dict[str, list] = defaultdict(list)

    for f in findings:
        if not f.resource_id:
            continue
        obs_time = f.captured_at or audit_at
        if obs_time > audit_at:
            continue
        ext = Path(f.abs_path).suffix.lower() if hasattr(f, 'abs_path') else ''
        src = 'log' if '.log' in f.file_id else (
               'sql' if '.sql' in f.file_id else (
               'json' if '.json' in f.file_id else 'txt'))
        pri = SOURCE_PRI.get(src, 2)
        obs[f.resource_id].append((obs_time, pri, f.state, f.file_id))

    # Add activity events as low-priority observations
    for evt in case_activities:
        if not evt.resource_id or not evt.event_time or evt.event_time > audit_at:
            continue
        if evt.reported_result != 'SUCCESS':
            continue
        EVT_STATE = {
            'DELETE_RECORD':     'ABSENT',
            'ANONYMIZE_RECORD':  'ANONYMIZED',
            'REDACT_RECORD':     'REDACTED',
            'BLOCK_RESTORE':     'BLOCKED',
            'DISABLE_DATA_FLOW': 'DISABLED',
        }
        state = EVT_STATE.get(evt.event_type)
        if state:
            obs[evt.resource_id].append(
                (evt.event_time, 1, state, f'activity_{evt.activity_id}')
            )

    result = {}
    for res_id, observations in obs.items():
        # Sort: most recent first; on tie, highest priority first
        observations.sort(key=lambda x: (x[0] or datetime.min.replace(tzinfo=timezone.utc), x[1]), reverse=True)

        # Check for resurrection: does a high-pri snapshot show PRESENT after any DELETE claim?
        delete_times = [t for t, p, s, _ in observations if s == 'ABSENT' and p >= 1]
        present_after_delete = any(
            s == 'PRESENT' and p >= 3 and (not delete_times or t >= max(delete_times))
            for t, p, s, _ in observations
        )

        if present_after_delete:
            # Find the evidence for the PRESENT observation
            for t, p, s, ev_id in observations:
                if s == 'PRESENT' and p >= 3:
                    result[res_id] = ('PRESENT', ev_id)
                    break
        else:
            t, p, s, ev_id = observations[0]
            result[res_id] = (s, ev_id)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

class DeletionAuditPipeline:

    def __init__(self, requests_csv: Optional[Path] = None):
        logger.info("Initializing pipeline...")
        self.usage = UsageTracker()
        self._gemini = self._init_gemini()
        self.requests_csv = requests_csv or DELETION_REQUESTS_CSV

        # Load CSVs
        self.requests = self._load_requests(self.requests_csv)
        self.identity_resolver = IdentityResolver(USER_IDENTITIES_CSV, USER_AUDIT_LOG_CSV)
        self.policy_engine = PolicyEngine(DELETION_RULES_CSV)
        self.activity_index = ActivityIndex(SYSTEM_ACTIVITY_CSV)
        self.evidence_manifest = load_evidence_manifest(EVIDENCE_FILES_CSV, DATASET_DIR)
        self.intent_classifier = IntentClassifier(self._gemini)

        logger.info(f"Loaded {len(self.requests)} requests, "
                    f"{len(self.evidence_manifest)} evidence files")

    # ── Gemini setup ──────────────────────────────────────────────────────────

    def _init_gemini(self):
        if not ENABLE_LLM:
            logger.info("No GEMINI_API_KEY — running in deterministic mode")
            return None
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            logger.info(f"Gemini initialized: {GEMINI_MODEL}")
            return model
        except Exception as e:
            logger.warning(f"Gemini init failed: {e}")
            return None

    # ── CSV loading ───────────────────────────────────────────────────────────

    def _load_requests(self, path: Optional[Path] = None) -> list:
        rows = []
        target_path = path or DELETION_REQUESTS_CSV
        with open(target_path, encoding='utf-8') as f:
            for row in csv.DictReader(f):
                rows.append(row)
        return rows

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> List[dict]:
        results = []
        total = len(self.requests)

        for i, req in enumerate(self.requests):
            case_id = req['case_id']
            try:
                status, steps = self._process_case(req)
                results.append({
                    'case_id': case_id,
                    'deletion_status': status,
                    'steps_json': steps_to_json(steps),
                })
                if (i + 1) % 50 == 0:
                    logger.info(f"Progress: {i+1}/{total} cases processed")
            except Exception as e:
                logger.error(f"Error on {case_id}: {e}", exc_info=True)
                results.append({
                    'case_id': case_id,
                    'deletion_status': 'INCOMPLETE',
                    'steps_json': '[]',
                })

        # Sort by case_id
        results.sort(key=lambda r: r['case_id'])
        return results

    # ── Per-case processing ───────────────────────────────────────────────────

    def _process_case(self, req: dict) -> Tuple[str, List[Step]]:
        case_id = req['case_id']
        email = req['email'].strip()
        audit_at = parse_dt(req['audit_at'])
        request_text = req['request_text']

        # 1. Intent classification
        intent = self.intent_classifier.classify(request_text)
        if not intent.is_deletion:
            logger.debug(f"{case_id}: NOT_APPLICABLE ({intent.reason})")
            return 'NOT_APPLICABLE', []

        # 2. Identity resolution
        identity = self.identity_resolver.resolve(email)
        if identity.match_type == 'UNRESOLVED':
            logger.warning(f"{case_id}: identity UNRESOLVED for {email}")

        all_emails = identity.all_emails
        all_phones = identity.all_phones
        all_hashes = identity.all_hashes
        user_id = identity.user_id

        # 3. Gather relevant activity events
        case_activities = self.activity_index.find_for_identity(
            all_emails, all_phones, all_hashes, user_id, audit_at
        )

        # 4. Extract all evidence findings
        all_findings: List[EvidenceFinding] = []
        for file_id, ef in self.evidence_manifest.items():
            # Skip evidence captured after audit_at
            if ef.captured_at and ef.captured_at > audit_at:
                continue
            try:
                findings = extract_evidence(
                    ef, all_emails, all_phones, all_hashes, user_id,
                    gemini_client=self._gemini
                )
                all_findings.extend(findings)
            except Exception as e:
                logger.debug(f"{case_id}: evidence {file_id} failed: {e}")

        # 5. Temporal state reconstruction
        resource_states = _reconstruct_state(all_findings, case_activities, audit_at)

        # 6. Data flow risk detection
        data_flow_risks = self.activity_index.detect_data_flow_risks(
            case_activities, all_emails, user_id, audit_at
        )

        # 7. Policy evaluation per resource
        violations: List[PolicyDecision] = []
        satisfied: List[PolicyDecision] = []

        # Build context for policy evaluation
        for resource_id, (current_state, evidence_id) in resource_states.items():
            system_id = _system_from_resource(resource_id)

            # Build context for condition evaluation
            context = {
                'audit_at': audit_at,
                'has_legal_hold': False,
            }

            # Check retention_until from evidence (security_audit_log)
            if resource_id.startswith('audit_record_'):
                ret = self._find_retention_until(resource_id, all_findings)
                if ret:
                    context['retention_until'] = ret

            dec = self.policy_engine.evaluate(resource_id, system_id, current_state, context)
            dec._evidence_id = evidence_id  # attach evidence for step generation

            if dec.required_action == 'SKIP':
                continue
            if dec.is_satisfied:
                satisfied.append(dec)
            else:
                violations.append(dec)

        # 8. Determine status
        if violations or data_flow_risks:
            status = 'INCOMPLETE'
        else:
            # Need at least some satisfied requirements to be COMPLETE
            if satisfied:
                status = 'COMPLETE'
            else:
                # No evidence at all → uncertain → INCOMPLETE conservatively
                status = 'INCOMPLETE'

        # 9. Build steps
        steps = build_steps(status, violations, satisfied, data_flow_risks)

        # 10. Validate
        errs = validate_steps(steps, status)
        if errs:
            for e in errs:
                logger.warning(f"{case_id}: step validation: {e}")

        return status, steps

    def _find_retention_until(self, resource_id: str, findings: List[EvidenceFinding]):
        """Extract retention_until from log evidence for security audit records."""
        from .evidence import parse_dt as _pdt
        for f in findings:
            if f.resource_id == resource_id:
                ret = f.raw.get('retention_until', '')
                if ret:
                    return _pdt(str(ret))
        return None

    # ── Output writing ────────────────────────────────────────────────────────

    def write_output(self, results: List[dict], path: Path = OUTPUT_PATH):
        # Validate row count
        assert len(results) == len(self.requests), \
            f"Row count mismatch: {len(results)} != {len(self.requests)}"

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
            writer.writeheader()
            writer.writerows(results)

        logger.info(f"✓ Wrote {len(results)} rows to {path}")

    def write_usage_report(self, path: Path):
        """Write usage_report.md."""
        path.parent.mkdir(parents=True, exist_ok=True)
        total = len(self.requests)
        avg_tokens = self.usage.total_tokens / total if total > 0 else 0
        avg_cost = self.usage.total_cost / total if total > 0 else 0

        content = f"""# Usage Report

## Full Dataset Run

**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
**Dataset size**: {total} deletion requests

## Model Configuration

| Setting | Value |
|---|---|
| Model provider | Google Gemini |
| Primary model | {GEMINI_MODEL} |
| Vision model | {GEMINI_MODEL} |
| LLM enabled | {ENABLE_LLM} |

## Token and Cost Summary

| Metric | Value |
|---|---|
| Total LLM calls | {len(self.usage.calls)} |
| Total input tokens | {sum(c['in_tokens'] for c in self.usage.calls):,} |
| Total output tokens | {sum(c['out_tokens'] for c in self.usage.calls):,} |
| Total tokens | {self.usage.total_tokens:,} |
| Average tokens per request | {avg_tokens:.0f} |
| Total estimated cost | ${self.usage.total_cost:.4f} |
| Average cost per request | ${avg_cost:.6f} |

## Per-Model Breakdown

{self.usage.summary()}

## Notes

- Most cases processed deterministically (CSV/SQL/JSON/LOG parsing, policy evaluation)
- LLM used only for: (1) multilingual intent classification, (2) PNG evidence extraction
- All LLM calls are cached by prompt hash to avoid redundant API calls
- Deterministic processing cost: $0.00
"""
        path.write_text(content, encoding='utf-8')
        logger.info(f"✓ Wrote usage report to {path}")
