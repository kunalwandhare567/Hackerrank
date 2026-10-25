"""
evaluator.py — Automated evaluation engine for Ghost Data Still Exists.
Evaluates sample cases against sample_output.csv and runs synthetic evaluation cases.
Run: python code/evaluation/evaluator.py
"""
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / 'code'))

from src import config as cfg
from src.pipeline import DeletionAuditPipeline
from src.policy import PolicyEngine, PolicyDecision
from src.planner import build_steps, steps_to_json, Step
from src.activity import DataFlowRisk

SAMPLE_REQUESTS = REPO_ROOT / 'dataset' / 'sample_deletion_requests.csv'
SAMPLE_OUTPUT   = REPO_ROOT / 'dataset' / 'sample_output.csv'
OUR_OUTPUT      = REPO_ROOT / 'output.csv'


def run_sample_benchmark():
    print(f"\n{'='*60}")
    print("  Benchmark 1: Sample Dataset Evaluation (32 Cases)")
    print(f"{'='*60}")
    
    # Run pipeline with sample requests
    pipeline = DeletionAuditPipeline(requests_csv=SAMPLE_REQUESTS)
    results = pipeline.run()

    with open(SAMPLE_OUTPUT, encoding='utf-8') as f:
        gt = {r['case_id']: r for r in csv.DictReader(f)}

    pred = {r['case_id']: r for r in results}
    common = sorted(set(gt.keys()) & set(pred.keys()))

    print(f"  Ground-truth sample cases : {len(gt)}")
    print(f"  Evaluated cases           : {len(common)}")

    # 1. Status accuracy & per-class metrics
    status_correct = 0
    status_wrong = []
    for cid in common:
        p_status = pred[cid]['deletion_status']
        g_status = gt[cid]['deletion_status']
        if p_status == g_status:
            status_correct += 1
        else:
            status_wrong.append((cid, g_status, p_status))

    acc = status_correct / len(common) if common else 0.0
    print(f"  Status accuracy           : {status_correct}/{len(common)} = {acc*100:.1f}%")

    print("\n  Per-Class Metrics:")
    for cls in ('COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'):
        tp = sum(1 for cid in common if pred[cid]['deletion_status'] == cls and gt[cid]['deletion_status'] == cls)
        fp = sum(1 for cid in common if pred[cid]['deletion_status'] == cls and gt[cid]['deletion_status'] != cls)
        fn = sum(1 for cid in common if pred[cid]['deletion_status'] != cls and gt[cid]['deletion_status'] == cls)
        prec = tp/(tp+fp) if (tp+fp) > 0 else 0.0
        rec  = tp/(tp+fn) if (tp+fn) > 0 else 0.0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
        print(f"    {cls:15s}  TP={tp:2d}  FP={fp:2d}  FN={fn:2d}  Precision={prec:.2f}  Recall={rec:.2f}  F1={f1:.2f}")

    # 2. Step accuracy for status-matched cases
    matched_cases = [cid for cid in common if pred[cid]['deletion_status'] == gt[cid]['deletion_status']]
    total_steps = 0
    correct_steps = 0
    extra_steps = 0
    missing_steps = 0
    exact_seq = 0

    for cid in matched_cases:
        pred_steps = json.loads(pred[cid]['steps_json'])
        gt_steps   = json.loads(gt[cid]['steps_json'])
        max_len = max(len(pred_steps), len(gt_steps))
        total_steps += max_len
        case_ok = True
        for i in range(max_len):
            if i >= len(pred_steps):
                missing_steps += 1
                case_ok = False
            elif i >= len(gt_steps):
                extra_steps += 1
                case_ok = False
            else:
                if _steps_match(pred_steps[i], gt_steps[i]):
                    correct_steps += 1
                else:
                    case_ok = False
        if case_ok:
            exact_seq += 1

    print(f"\n  Step-level accuracy       : {correct_steps}/{total_steps} = {correct_steps/total_steps*100:.1f}%" if total_steps else "  No steps")
    print(f"  Exact sequence matches    : {exact_seq}/{len(matched_cases)}")
    print(f"  Missing predicted steps   : {missing_steps}")
    print(f"  Extra predicted steps     : {extra_steps}")

    return acc


def _steps_match(p, g) -> bool:
    for field in ('phase', 'system_id', 'resource_id', 'operation', 'state'):
        if p.get(field) != g.get(field):
            return False
    p_ev = bool(p.get('evidence_id', ''))
    g_ev = bool(g.get('evidence_id', ''))
    if p_ev != g_ev:
        return False
    if p_ev and g_ev and p.get('evidence_id') != g.get('evidence_id'):
        return False
    return True


def run_synthetic_cases():
    print(f"\n{'='*60}")
    print("  Benchmark 2: Synthetic Evaluation Cases")
    print(f"{'='*60}")

    passed = 0
    pe = PolicyEngine(cfg.DELETION_RULES_CSV)

    # Synthetic Case 1: Historical identifier that survives deletion
    # User updated email; old email survives in search_service search_9999 as PRESENT.
    print("\n  [Synthetic Case 1] Historical Identifier Survival")
    # search_9999 is category SEARCH_INDEX_ENTRY -> requires DELETE -> ABSENT. Since it is PRESENT, it is a violation.
    dec1 = pe.evaluate('search_9999', 'search_service', 'PRESENT', {})
    dec1._evidence_id = 'evidence_syn_01'
    status1 = 'INCOMPLETE' if not dec1.is_satisfied else 'COMPLETE'
    steps1 = build_steps(status1, [dec1], [], [])
    c1_ok = (status1 == 'INCOMPLETE' and 
             any(s.operation == 'REPORT_REMAINING_RECORD' and s.resource_id == 'search_9999' for s in steps1) and
             any(s.operation == 'DELETE_RECORD' and s.resource_id == 'search_9999' for s in steps1))
    print(f"    Expected: INCOMPLETE with REPORT_REMAINING_RECORD & DELETE_RECORD on search_9999")
    print(f"    Observed: Status={status1}, Steps={len(steps1)}")
    print(f"    Result: {'PASS' if c1_ok else 'FAIL'}")
    if c1_ok: passed += 1

    # Synthetic Case 2: Active synchronization or restore path that can recreate data
    # All records absent, but active sync data flow detected.
    print("\n  [Synthetic Case 2] Active Synchronization / Restore Risk")
    dec2 = pe.evaluate('account_1002', 'account_service', 'ABSENT', {})
    dec2._evidence_id = 'evidence_syn_02'
    flow_risk = DataFlowRisk(
        resource_id='data_flow_syn_99',
        flow_type='SYNC',
        state='ACTIVE',
        evidence_id='activity_syn_01',
        system_id='integration_service'
    )
    status2 = 'INCOMPLETE'  # active data flow makes it incomplete
    steps2 = build_steps(status2, [], [dec2], [flow_risk])
    c2_ok = (status2 == 'INCOMPLETE' and
             any(s.operation == 'REPORT_ACTIVE_DATA_FLOW' for s in steps2) and
             any(s.operation == 'DISABLE_DATA_FLOW' for s in steps2))
    print(f"    Expected: INCOMPLETE with REPORT_ACTIVE_DATA_FLOW and DISABLE_DATA_FLOW")
    print(f"    Observed: Status={status2}, Steps={len(steps2)}")
    print(f"    Result: {'PASS' if c2_ok else 'FAIL'}")
    if c2_ok: passed += 1

    # Synthetic Case 3: Retained record containing identifiers that must be redacted
    # Support message is PRESENT -> policy mandates REDACT -> REDACTED.
    print("\n  [Synthetic Case 3] Retained Record Requiring Redaction")
    dec3 = pe.evaluate('support_ticket_888', 'support_platform', 'PRESENT', {})
    dec3._evidence_id = 'evidence_syn_03'
    status3 = 'INCOMPLETE' if not dec3.is_satisfied else 'COMPLETE'
    steps3 = build_steps(status3, [dec3], [], [])
    c3_ok = (status3 == 'INCOMPLETE' and
             any(s.operation == 'REPORT_EXPOSED_PII' for s in steps3) and
             any(s.operation == 'REDACT_RECORD' for s in steps3) and
             any(s.operation == 'VERIFY_RECORD_REDACTED' for s in steps3))
    print(f"    Expected: INCOMPLETE with REPORT_EXPOSED_PII -> REDACT_RECORD -> VERIFY_RECORD_REDACTED")
    print(f"    Observed: Status={status3}, Steps={len(steps3)}")
    print(f"    Result: {'PASS' if c3_ok else 'FAIL'}")
    if c3_ok: passed += 1

    print(f"\n  Synthetic Cases Passed: {passed}/3")
    return passed == 3


def validate_production_output():
    print(f"\n{'='*60}")
    print("  Benchmark 3: Production output.csv Validation")
    print(f"{'='*60}")
    if not OUR_OUTPUT.exists():
        print("  output.csv not found!")
        return False
    with open(OUR_OUTPUT, encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    print(f"  Total production rows : {len(rows)}")
    valid_status = all(r['deletion_status'] in ('COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE') for r in rows)
    sorted_ok = [r['case_id'] for r in rows] == sorted(r['case_id'] for r in rows)
    print(f"  Valid statuses        : {valid_status}")
    print(f"  Sorted by case_id     : {sorted_ok}")
    return len(rows) == 518 and valid_status and sorted_ok


if __name__ == '__main__':
    acc = run_sample_benchmark()
    syn_ok = run_synthetic_cases()
    prod_ok = validate_production_output()
    print(f"\n{'='*60}")
    print(f"  EVALUATION SUMMARY:")
    print(f"    Sample Benchmark Accuracy : {acc*100:.1f}%")
    print(f"    Synthetic Test Cases      : {'ALL PASSED (3/3)' if syn_ok else 'FAILED'}")
    print(f"    Production Output Check   : {'PASS (518 rows)' if prod_ok else 'FAIL'}")
    print(f"{'='*60}\n")
    sys.exit(0 if acc >= 0.5 and syn_ok and prod_ok else 1)
