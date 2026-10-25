# HackerRank Orchestrate - October 2026
## Ghost Data Still Exists — Autonomous Deletion Audit Agent

An enterprise-grade, deterministic + AI-assisted deletion audit pipeline that audits personal data deletion compliance, identifies "ghost data" across heterogeneous systems, flags active data replication/sync risks, and produces strictly phase-ordered remediation plans.

---

## 🎯 Challenge Summary

A deletion workflow may report **Complete** while user personal data persists across:
- **Primary & Replica Databases**: Unsynchronized replication drift across regional, reporting, and failover replicas.
- **Search Indexes & Export Caches**: Stale indexes, JSON exports, and cached profiles.
- **Support Platforms & Attachments**: Unredacted support tickets, customer references, and transaction logs.
- **Backups & Archives**: Backups with active restore capability (`restore_allowed = 1`) or unblocked recovery pathways.
- **Active Data Sync / Streams**: Ongoing background synchronization processes that recreate deleted accounts.

For every deletion request, the agent:
1. Evaluates deletion scope and request intent (`COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`).
2. Traces current and historical user identities (emails, phone numbers, salted hashes, and audit histories).
3. Inspects multi-modal evidence across 94 evidence files (SQL schemas, JSON exports, logs, support tickets, PDFs).
4. Detects active synchronization and restore recreation risks.
5. Enforces corporate retention policies (15 deletion rules) and distinguishes compliant redaction from exposed PII.
6. Emits a valid, strictly ordered JSON array of `FINDING`, `REMEDIATION`, and `VERIFICATION` steps.

---

## 🏗️ Architecture & Pipeline Design

The system implements a **Hybrid Architecture** combining deterministic rule engines (for schema correctness, policy enforcement, and step sequencing) with AI reasoning (for unstructured evidence and edge-case ambiguity):

```
                                 [ Deletion Request ]
                                          │
                                          ▼
                             ┌─────────────────────────┐
                             │    Intent Classifier    │  ── Fast keyword filter + LLM fallback
                             │       (intent.py)       │
                             └────────────┬────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
      ┌─────────────────────────┐                     ┌─────────────────────────┐
      │    Identity Resolver    │                     │     Activity Index      │
      │      (identity.py)      │                     │      (activity.py)      │
      │ Multi-hop user audit log│                     │  4,000+ system events,  │
      │ emails, phones, hashes  │                     │ active sync/restore risk│
      └───────────┬─────────────┘                     └───────────┬─────────────┘
                  │                                               │
                  └───────────────────────┬───────────────────────┘
                                          │
                                          ▼
                             ┌─────────────────────────┐
                             │ Evidence Parsing Engine │  ── SQL (SQLite replica diffing)
                             │      (evidence.py)      │  ── JSON, Logs, Support Tickets
                             │  + AI Semantic Reasoner │  ── PDF extraction & Redaction check
                             └────────────┬────────────┘
                                          │
                                          ▼
                             ┌─────────────────────────┐
                             │      Policy Engine      │  ── 15 corporate deletion rules
                             │       (policy.py)       │  ── Retention exemptions & guards
                             └────────────┬────────────┘
                                          │
                                          ▼
                             ┌─────────────────────────┐
                             │  Phase-Ordered Planner  │  ── FINDING -> REMEDIATION -> VERIFICATION
                             │      (planner.py)       │  ── 1-indexed, deterministic sort order
                             └────────────┬────────────┘
                                          │
                                          ▼
                                   [ output.csv ]
```

### Core Modules (`code/src/`)

1. **`identity.py` (`IdentityResolver`)**:
   - Resolves current identities from `user_identities.csv`.
   - Reconstructs historical identity evolutions across `user_audit_log.csv` (previous emails, phone numbers, and SHA-256 phone hashes).
   - Scopes queries strictly to timestamps up to `audit_at`.

2. **`evidence.py` (`EvidenceEngine`)**:
   - **SQL Snapshots**: Executes in-memory SQLite instances to verify primary vs regional, reporting, and failover replicas (`evidence_54`). Analyzes database column flags (`restore_allowed`, `enabled`).
   - **JSON Exports**: Extracts multi-user JSON payloads, tracking pseudonymized customer references (`customer_reference`) vs unredacted raw PII.
   - **Support Tickets & Text**: Distinguishes between redacted records (null/redacted PII) and exposed data.
   - **Logs & PDFs**: Regex parsing for authentication events, export triggers, and document text.

3. **`activity.py` (`ActivityIndex`)**:
   - Indexes 4,011 system activity events.
   - Flags active data flows (`ACTIVE_SYNC`, `RESTORE_TRIGGER`) occurring near or after the deletion timestamp, identifying recreation hazards.

4. **`policy.py` (`PolicyEngine`)**:
   - Evaluates all 15 corporate deletion rules (`deletion_rules.csv`).
   - Maps data categories to system IDs, required retention states, and allowed remediation operations.
   - Enforces backup archive exceptions (allowing retained records if restore pathways are blocked).

5. **`intent.py` (`IntentClassifier`)**:
   - Classifies user requests to ensure confirmation inquiries or audit status checks are correctly recognized as in-scope deletion audits, reserving `NOT_APPLICABLE` for non-deletion inquiries.

6. **`agent_reasoner.py` (`AgentReasoner`)**:
   - Houses the Gemini/Gemma LLM integration with SHA-256 caching.
   - Invoked for ambiguous semantic reasoning while guaranteeing deterministic fallback.

7. **`planner.py` (`PlanGenerator`)**:
   - Generates schema-compliant remediation plans.
   - Strictly enforces phase ordering: `FINDING` ➔ `REMEDIATION` ➔ `VERIFICATION`.
   - Assigns 1-indexed consecutive step numbers, verified evidence IDs on findings, and empty evidence strings (`""`) on future remediation actions.

8. **`pipeline.py` & `main.py`**:
   - Orchestrates processing of all 518 cases with progress logging and output validation.

---

## 📊 Benchmark & Evaluation Results

### Ground-Truth Sample Benchmark (32 Cases)
- **Status Accuracy**: **84.4% (27/32)** *(Up from 65.6% baseline)*
- **COMPLETE Cases**: Precision = 0.86, Recall = 0.60, F1 = 0.71
- **INCOMPLETE Cases**: Precision = 0.84, Recall = 0.95, F1 = 0.89

### Custom Synthetic Evaluation Cases
The evaluation suite includes 3 comprehensive synthetic test scenarios (`code/evaluation/evaluator.py`):
1. **Historical Identifier Survival**: User changed email prior to deletion; search index retained old email record.
   - **Result**: ✅ **PASS** (Correctly identified as `INCOMPLETE` with `REPORT_REMAINING_RECORD` & `DELETE_RECORD`).
2. **Active Synchronization / Restore Risk**: System has active background sync stream after deletion request.
   - **Result**: ✅ **PASS** (Correctly identified as `INCOMPLETE` with `REPORT_ACTIVE_DATA_FLOW` & `DISABLE_DATA_FLOW`).
3. **Retained Record Requiring Redaction**: Record retained for legal/audit purposes with unredacted PII.
   - **Result**: ✅ **PASS** (Correctly identified as `INCOMPLETE` with `REPORT_EXPOSED_PII` ➔ `REDACT_RECORD` ➔ `VERIFY_RECORD_REDACTED`).

### Production Run Validation (`output.csv`)
- **Total Cases Processed**: 518 (`case_100` to `case_617`)
- **JSON Validity**: 100% valid JSON arrays
- **Schema & Ordering**: 100% compliant with problem statement specification

---

## 🚀 Setup & Execution

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.11, 3.12, 3.13)
- Windows, macOS, or Linux

### 2. Environment Setup
Create and activate a virtual environment:

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### 3. API Key Configuration (Optional)
To enable AI reasoning capabilities, provide a Google Generative AI API key in a `.env` file at the root:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```
*(The pipeline operates deterministically even if no API key is provided, falling back to rule-based semantic inference).*

### 4. Running the Pipeline
Run the main script to process all 518 deletion requests and generate `output.csv`:

```bash
python code/main.py
```

### 5. Running Evaluations
Run the automated evaluation suite to verify accuracy against ground-truth samples and synthetic test cases:

```bash
python code/evaluation/evaluator.py
```

### 6. Running Submission Pre-Flight Checks
Verify all submission files before uploading:

```bash
python checklist.py
```

---

## 📦 Submission Artifacts

| File | Description | Destination Slot |
| :--- | :--- | :--- |
| **`output.csv`** | 518 predicted cases sorted by `case_id` with valid `steps_json` | Output File |
| **`code.zip`** | Clean zip containing `code/` and `README.md` (no datasets, no `__pycache__`) | Code Bundle |
| **`log.txt`** | Full interaction transcript formatted according to `AGENTS.md` | Chat Transcript |
| **`evaluation/evaluation_report.md`** | Comprehensive accuracy breakdown, synthetic cases, and failure analysis | Code Bundle |
| **`evaluation/usage_report.md`** | Model token usage, API call metrics, and cost breakdown | Code Bundle |

### Packaging `code.zip`
To regenerate the submission archive cleanly:

**macOS / Linux:**
```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*"
```

**Windows (PowerShell):**
```powershell
Get-ChildItem -Path code -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```
