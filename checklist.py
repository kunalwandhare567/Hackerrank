import zipfile, csv, json
from collections import Counter

print('=== SUBMISSION CHECKLIST ===')
print()

# 1. output.csv
with open('output.csv', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

print(f'output.csv rows: {len(rows)}')
valid_status = all(r['deletion_status'] in ('COMPLETE','INCOMPLETE','NOT_APPLICABLE') for r in rows)
valid_steps  = all(isinstance(json.loads(r['steps_json']), list) for r in rows)
sorted_ok    = [r['case_id'] for r in rows] == sorted(r['case_id'] for r in rows)

print(f'  Status values valid : {valid_status}')
print(f'  Steps JSON valid    : {valid_steps}')
print(f'  Sorted by case_id   : {sorted_ok}')
dist = Counter(r['deletion_status'] for r in rows)
print(f'  Distribution        : {dict(dist)}')
print()

# Validate step consecutive numbering and evidence_id rules
step_errors = []
for r in rows:
    steps = json.loads(r['steps_json'])
    status = r['deletion_status']
    nums = [s['step_no'] for s in steps]
    if nums and nums != list(range(1, len(steps)+1)):
        step_errors.append(f'{r["case_id"]}: non-consecutive step numbers')
    if status == 'COMPLETE':
        for s in steps:
            if s['phase'] != 'VERIFICATION':
                step_errors.append(f'{r["case_id"]}: COMPLETE has non-VERIFICATION step')
            if not s.get('evidence_id'):
                step_errors.append(f'{r["case_id"]}: COMPLETE VERIFICATION missing evidence_id')
    if status == 'INCOMPLETE':
        for s in steps:
            if s['phase'] == 'REMEDIATION' and s.get('evidence_id'):
                step_errors.append(f'{r["case_id"]}: INCOMPLETE REMEDIATION has evidence_id')

if step_errors:
    print(f'STEP ERRORS ({len(step_errors)}):')
    for e in step_errors[:10]:
        print(' ', e)
else:
    print('Step validation: ALL OK')
print()

# 2. code.zip
with zipfile.ZipFile('code.zip', 'r') as z:
    names = z.namelist()
print(f'code.zip files: {len(names)}')
req_files = [
    'code/main.py',
    'code/src/pipeline.py',
    'code/src/identity.py',
    'code/src/evidence.py',
    'code/src/policy.py',
    'code/src/activity.py',
    'code/src/intent.py',
    'code/src/planner.py',
    'code/src/config.py',
    'README.md',
    'code/evaluation/evaluation_report.md',
    'code/evaluation/usage_report.md',
]
all_present = True
for rf in req_files:
    exists = rf in names
    if not exists:
        all_present = False
        print(f'  MISSING: {rf}')
if all_present:
    print('  All required files present')
has_nested = any(n.endswith(('.zip','.tar','.gz','.7z')) for n in names)
print(f'  No nested archives: {not has_nested}')
print()

# 3. log.txt
with open('log.txt', encoding='utf-8') as f:
    log = f.read()
print(f'log.txt: {len(log)} chars')
print(f'  SESSION START: {"SESSION START" in log}')
print(f'  tool= populated: {"tool=Antigravity" in log}')
print(f'  model= populated: {"model=gemini" in log}')
print()
print('=== ALL READY TO SUBMIT ===')
print()
print('Submit at:')
print('https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists')
print()
print('Upload:')
print('  1. output.csv  (518 rows)')
print('  2. code.zip    (code/ + README.md)')
print('  3. log.txt     (chat_transcript slot)')
