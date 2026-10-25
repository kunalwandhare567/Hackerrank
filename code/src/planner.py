"""
planner.py — Remediation planner and step serializer.
Generates the exact steps_json array from a case decision.
"""
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# ── Phase ordering ────────────────────────────────────────────────────────────
PHASE_ORDER = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}

# ── Operation ordering within phase ──────────────────────────────────────────
OPERATION_ORDER = {
    # FINDING
    'REPORT_REMAINING_RECORD': 1,
    'REPORT_EXPOSED_PII':      2,
    'REPORT_ACTIVE_DATA_FLOW': 3,
    'REPORT_RESTORE_RISK':     4,
    # REMEDIATION
    'DISABLE_DATA_FLOW': 1,
    'BLOCK_RESTORE':     2,
    'DELETE_RECORD':     3,
    'REDACT_RECORD':     4,
    'ANONYMIZE_RECORD':  5,
    # VERIFICATION
    'VERIFY_RECORD_ABSENT':    1,
    'VERIFY_RECORD_PRESENT':   2,
    'VERIFY_RECORD_REDACTED':  3,
    'VERIFY_RECORD_ANONYMIZED':4,
    'VERIFY_DATA_FLOW_DISABLED':5,
    'VERIFY_RESTORE_BLOCKED':  6,
}

# ── Valid (phase, operation, state) triples ───────────────────────────────────
VALID_COMBOS = {
    ('FINDING',      'REPORT_REMAINING_RECORD',  'PRESENT'),
    ('FINDING',      'REPORT_EXPOSED_PII',        'PRESENT'),
    ('FINDING',      'REPORT_ACTIVE_DATA_FLOW',   'ACTIVE'),
    ('FINDING',      'REPORT_RESTORE_RISK',        'ACTIVE'),
    ('REMEDIATION',  'DISABLE_DATA_FLOW',          'DISABLED'),
    ('REMEDIATION',  'BLOCK_RESTORE',              'BLOCKED'),
    ('REMEDIATION',  'DELETE_RECORD',              'ABSENT'),
    ('REMEDIATION',  'REDACT_RECORD',              'REDACTED'),
    ('REMEDIATION',  'ANONYMIZE_RECORD',           'ANONYMIZED'),
    ('VERIFICATION', 'VERIFY_RECORD_ABSENT',       'ABSENT'),
    ('VERIFICATION', 'VERIFY_RECORD_PRESENT',      'PRESENT'),
    ('VERIFICATION', 'VERIFY_RECORD_REDACTED',     'REDACTED'),
    ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED',   'ANONYMIZED'),
    ('VERIFICATION', 'VERIFY_DATA_FLOW_DISABLED',  'DISABLED'),
    ('VERIFICATION', 'VERIFY_RESTORE_BLOCKED',     'BLOCKED'),
}

OP_TO_STATE = {
    'DELETE_RECORD':     'ABSENT',
    'REDACT_RECORD':     'REDACTED',
    'ANONYMIZE_RECORD':  'ANONYMIZED',
    'DISABLE_DATA_FLOW': 'DISABLED',
    'BLOCK_RESTORE':     'BLOCKED',
}

STATE_TO_VERIFY = {
    'ABSENT':     'VERIFY_RECORD_ABSENT',
    'REDACTED':   'VERIFY_RECORD_REDACTED',
    'ANONYMIZED': 'VERIFY_RECORD_ANONYMIZED',
    'PRESENT':    'VERIFY_RECORD_PRESENT',
    'DISABLED':   'VERIFY_DATA_FLOW_DISABLED',
    'BLOCKED':    'VERIFY_RESTORE_BLOCKED',
}


@dataclass
class Step:
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str
    step_no: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'step_no':     self.step_no,
            'phase':       self.phase,
            'system_id':   self.system_id,
            'resource_id': self.resource_id,
            'operation':   self.operation,
            'state':       self.state,
            'evidence_id': self.evidence_id,
        }


def _sort_steps(steps: List[Step]) -> List[Step]:
    """Sort by phase → operation order → system_id → resource_id."""
    def key(s: Step):
        return (
            PHASE_ORDER.get(s.phase, 9),
            OPERATION_ORDER.get(s.operation, 99),
            s.system_id or '',
            s.resource_id or '',
        )
    sorted_steps = sorted(steps, key=key)
    for i, s in enumerate(sorted_steps, 1):
        s.step_no = i
    return sorted_steps


def _dedup_steps(steps: List[Step]) -> List[Step]:
    """Remove duplicate steps (same phase+operation+system_id+resource_id)."""
    seen = set()
    result = []
    for s in steps:
        key = (s.phase, s.operation, s.system_id, s.resource_id)
        if key not in seen:
            seen.add(key)
            result.append(s)
    return result


def build_steps(
    status: str,
    violations: list,           # list of PolicyDecision (is_satisfied=False)
    satisfied: list,            # list of PolicyDecision (is_satisfied=True)
    data_flow_risks: list,      # list of DataFlowRisk
) -> List[Step]:
    """
    Generate all steps based on status.
    COMPLETE   → only VERIFICATION steps (all satisfied)
    INCOMPLETE → FINDING + REMEDIATION + VERIFICATION
    NOT_APPLICABLE → []
    """
    if status == 'NOT_APPLICABLE':
        return []

    if status == 'COMPLETE':
        return _build_complete_steps(satisfied, data_flow_risks)

    return _build_incomplete_steps(violations, satisfied, data_flow_risks)


def _build_complete_steps(satisfied: list, data_flow_risks: list) -> List[Step]:
    steps = []
    for dec in satisfied:
        if dec.required_action == 'SKIP':
            continue
        v_op = dec.verification_op
        if not v_op:
            continue
        state = dec.required_state
        if not state:
            continue
        ev_id = getattr(dec, '_evidence_id', '') or ''
        if not ev_id:
            continue  # COMPLETE verification MUST have evidence
        steps.append(Step(
            phase='VERIFICATION',
            system_id=dec.system_id,
            resource_id=dec.resource_id,
            operation=v_op,
            state=state,
            evidence_id=ev_id,
        ))
    steps = _dedup_steps(steps)
    return _sort_steps(steps)


def _build_incomplete_steps(violations: list, satisfied: list, data_flow_risks: list) -> List[Step]:
    finding_steps = []
    remediation_steps = []
    verification_steps = []

    # ── Findings for policy violations ───────────────────────────────────────
    for dec in violations:
        if dec.required_action in ('SKIP', 'UNKNOWN'):
            continue
        vf = dec.violation_finding
        if not vf:
            continue
        state = 'PRESENT'
        finding_steps.append(Step(
            phase='FINDING',
            system_id=dec.system_id,
            resource_id=dec.resource_id,
            operation=vf,
            state=state,
            evidence_id=getattr(dec, '_evidence_id', '') or '',
        ))

    # ── Findings for data flow risks ──────────────────────────────────────────
    for risk in data_flow_risks:
        op = 'REPORT_RESTORE_RISK' if risk.flow_type in ('RESTORE', 'RESTORE_EXECUTED') else 'REPORT_ACTIVE_DATA_FLOW'
        finding_steps.append(Step(
            phase='FINDING',
            system_id=risk.system_id,
            resource_id=risk.resource_id,
            operation=op,
            state='ACTIVE',
            evidence_id=risk.evidence_id,
        ))

    # ── Remediation: data flows first, then restores, then records ────────────
    for risk in data_flow_risks:
        if risk.flow_type in ('SYNC', 'CONNECTOR'):
            remediation_steps.append(Step(
                phase='REMEDIATION',
                system_id=risk.system_id,
                resource_id=risk.resource_id,
                operation='DISABLE_DATA_FLOW',
                state='DISABLED',
                evidence_id='',
            ))
        elif risk.flow_type in ('RESTORE', 'RESTORE_EXECUTED'):
            remediation_steps.append(Step(
                phase='REMEDIATION',
                system_id='backup_service',
                resource_id=risk.resource_id,
                operation='BLOCK_RESTORE',
                state='BLOCKED',
                evidence_id='',
            ))

    for dec in violations:
        if dec.required_action in ('SKIP', 'RETAIN', 'UNKNOWN'):
            continue
        r_op = dec.remediation_op
        if not r_op:
            continue
        state = OP_TO_STATE.get(r_op, 'ABSENT')
        remediation_steps.append(Step(
            phase='REMEDIATION',
            system_id=dec.system_id,
            resource_id=dec.resource_id,
            operation=r_op,
            state=state,
            evidence_id='',
        ))

    # ── Verification: violations (future) + satisfied RETAIN (must still exist) ──
    # Violations: what needs to be verified after remediation
    for dec in violations:
        if dec.required_action in ('SKIP', 'UNKNOWN'):
            continue
        v_op = dec.verification_op
        if not v_op:
            continue
        state = dec.required_state
        if not state:
            continue
        verification_steps.append(Step(
            phase='VERIFICATION',
            system_id=dec.system_id,
            resource_id=dec.resource_id,
            operation=v_op,
            state=state,
            evidence_id='',
        ))

    # Satisfied RETAIN records (security_audit_log etc.) → VERIFY_RECORD_PRESENT
    for dec in satisfied:
        if dec.required_action == 'RETAIN':
            v_op = dec.verification_op
            state = dec.required_state
            if v_op and state:
                verification_steps.append(Step(
                    phase='VERIFICATION',
                    system_id=dec.system_id,
                    resource_id=dec.resource_id,
                    operation=v_op,
                    state=state,
                    evidence_id='',
                ))

    # Data flows: verification
    for risk in data_flow_risks:
        if risk.flow_type in ('SYNC', 'CONNECTOR'):
            verification_steps.append(Step(
                phase='VERIFICATION',
                system_id=risk.system_id,
                resource_id=risk.resource_id,
                operation='VERIFY_DATA_FLOW_DISABLED',
                state='DISABLED',
                evidence_id='',
            ))
        elif risk.flow_type in ('RESTORE', 'RESTORE_EXECUTED'):
            verification_steps.append(Step(
                phase='VERIFICATION',
                system_id='backup_service',
                resource_id=risk.resource_id,
                operation='VERIFY_RESTORE_BLOCKED',
                state='BLOCKED',
                evidence_id='',
            ))

    all_steps = finding_steps + remediation_steps + verification_steps
    all_steps = _dedup_steps(all_steps)
    return _sort_steps(all_steps)


def steps_to_json(steps: List[Step]) -> str:
    """Serialize steps to JSON string."""
    return json.dumps([s.to_dict() for s in steps], ensure_ascii=False)


def validate_steps(steps: List[Step], status: str) -> List[str]:
    """Return list of error strings (empty = valid)."""
    errors = []

    if status == 'NOT_APPLICABLE':
        if steps:
            errors.append("NOT_APPLICABLE must have empty steps")
        return errors

    if status == 'COMPLETE':
        for s in steps:
            if s.phase != 'VERIFICATION':
                errors.append(f"COMPLETE has non-VERIFICATION step: {s}")
            if not s.evidence_id:
                errors.append(f"COMPLETE VERIFICATION step missing evidence_id: {s}")

    for s in steps:
        combo = (s.phase, s.operation, s.state)
        if combo not in VALID_COMBOS:
            errors.append(f"Invalid combo: {combo}")
        if status == 'INCOMPLETE' and s.phase in ('REMEDIATION',) and s.evidence_id:
            errors.append(f"INCOMPLETE REMEDIATION step should have empty evidence_id: {s}")

    nums = [s.step_no for s in steps]
    if nums and nums != list(range(1, len(steps) + 1)):
        errors.append(f"Step numbers not consecutive: {nums}")

    return errors
