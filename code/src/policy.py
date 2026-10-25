"""
policy.py — Policy engine for Ghost Data Still Exists.
Loads deletion_rules.csv and evaluates compliance per resource.
"""
import csv
import logging
import re
from dataclasses import dataclass
from typing import Optional, Dict

logger = logging.getLogger(__name__)


# ── Resource-ID prefix → data_category ──────────────────────────────────────
RESOURCE_CATEGORY_MAP: Dict[str, str] = {
    'account_':        'USER_PROFILE',
    'search_':         'SEARCH_INDEX_ENTRY',
    'analytics_':      'ANALYTICS_PROFILE',
    'support_':        'SUPPORT_MESSAGE',
    'audit_record_':   'SECURITY_AUDIT_LOG',
    'backup_':         'BACKUP_ARCHIVE',
    'export_':         'USER_EXPORT',
    'cache_':          'CACHE_ENTRY',
    'marketing_':      'MARKETING_PROFILE',
    'tombstone_':      'ACCOUNT_TOMBSTONE',
    'email_delivery_': 'EMAIL_DELIVERY_LOG',
    'telemetry_':      'PRODUCT_TELEMETRY',
    'data_flow_':      'DATA_FLOW',          # integration_service connectors
    'legal_hold_':     'LEGAL_HOLD_RECORD',  # legal holds
}

# ── System → default category override (for cases where prefix is ambiguous) ─
SYSTEM_CATEGORY_OVERRIDE: Dict[str, str] = {
    'security_service': 'SECURITY_AUDIT_LOG',
    'identity_service': 'ACCOUNT_TOMBSTONE',
    'marketing_platform': 'MARKETING_PROFILE',
    'cache_service': 'CACHE_ENTRY',
    'export_service': 'USER_EXPORT',
}

# ── Required final state per action ─────────────────────────────────────────
ACTION_TO_STATE = {
    'DELETE':   'ABSENT',
    'REDACT':   'REDACTED',
    'ANONYMIZE':'ANONYMIZED',
    'RETAIN':   'PRESENT',
}

# ── Violation type per action ─────────────────────────────────────────────────
ACTION_TO_FINDING = {
    'DELETE':    'REPORT_REMAINING_RECORD',
    'REDACT':    'REPORT_EXPOSED_PII',
    'ANONYMIZE': 'REPORT_EXPOSED_PII',
    'RETAIN':    'REPORT_REMAINING_RECORD',   # missing retained record
}

# ── Remediation operation per action ─────────────────────────────────────────
ACTION_TO_REMEDIATION = {
    'DELETE':    'DELETE_RECORD',
    'REDACT':    'REDACT_RECORD',
    'ANONYMIZE': 'ANONYMIZE_RECORD',
    'RETAIN':    None,    # no active remediation needed — it should already exist
}

# ── Verification operation per required_state ────────────────────────────────
STATE_TO_VERIFICATION = {
    'ABSENT':     'VERIFY_RECORD_ABSENT',
    'REDACTED':   'VERIFY_RECORD_REDACTED',
    'ANONYMIZED': 'VERIFY_RECORD_ANONYMIZED',
    'PRESENT':    'VERIFY_RECORD_PRESENT',
    'DISABLED':   'VERIFY_DATA_FLOW_DISABLED',
    'BLOCKED':    'VERIFY_RESTORE_BLOCKED',
}


@dataclass
class PolicyDecision:
    rule_id: Optional[str]
    category: str
    required_action: str            # DELETE | REDACT | ANONYMIZE | RETAIN | SKIP | UNKNOWN
    required_state: Optional[str]   # ABSENT | REDACTED | ANONYMIZED | PRESENT
    is_satisfied: bool
    violation_finding: Optional[str]    # REPORT_REMAINING_RECORD | REPORT_EXPOSED_PII
    remediation_op: Optional[str]       # DELETE_RECORD | REDACT_RECORD | ANONYMIZE_RECORD
    verification_op: Optional[str]      # VERIFY_RECORD_ABSENT | ...
    system_id: str = ''
    resource_id: str = ''


class PolicyEngine:
    """
    Loads 15 policy rules and evaluates compliance.
    """

    def __init__(self, rules_path):
        self._rules: Dict[str, dict] = {}
        with open(rules_path, encoding='utf-8') as f:
            for row in csv.DictReader(f):
                self._rules[row['data_category']] = {
                    'rule_id':        row['rule_id'],
                    'condition':      row['condition'],
                    'required_action': row['required_action'],
                }

    def classify_resource(self, resource_id: str, system_id: str) -> str:
        """Map resource_id to data_category."""
        for prefix, cat in RESOURCE_CATEGORY_MAP.items():
            if resource_id.startswith(prefix):
                return cat
        # Fallback: system-based
        cat = SYSTEM_CATEGORY_OVERRIDE.get(system_id)
        if cat:
            return cat
        return 'UNKNOWN'

    def evaluate(
        self,
        resource_id: str,
        system_id: str,
        current_state: str,         # PRESENT | ABSENT | ANONYMIZED | REDACTED | BLOCKED | DISABLED | ACTIVE
        context: dict,              # extra flags: retention_until, has_legal_hold, etc.
    ) -> PolicyDecision:

        category = self.classify_resource(resource_id, system_id)

        if category in ('UNKNOWN', 'DATA_FLOW'):
            # DATA_FLOW handled by data flow analyzer; UNKNOWN = skip conservatively
            return PolicyDecision(
                rule_id=None,
                category=category,
                required_action='SKIP',
                required_state=None,
                is_satisfied=True,
                violation_finding=None,
                remediation_op=None,
                verification_op=None,
                system_id=system_id,
                resource_id=resource_id,
            )

        if category not in self._rules:
            # No rule → skip
            return PolicyDecision(
                rule_id=None, category=category, required_action='SKIP',
                required_state=None, is_satisfied=True,
                violation_finding=None, remediation_op=None, verification_op=None,
                system_id=system_id, resource_id=resource_id,
            )

        rule = self._rules[category]
        required_action = rule['required_action']
        condition = rule['condition']

        # Evaluate condition
        condition_met = self._eval_condition(condition, current_state, context)
        if not condition_met:
            # Rule's condition not met → skip
            return PolicyDecision(
                rule_id=rule['rule_id'], category=category, required_action='SKIP',
                required_state=None, is_satisfied=True,
                violation_finding=None, remediation_op=None, verification_op=None,
                system_id=system_id, resource_id=resource_id,
            )

        required_state = ACTION_TO_STATE.get(required_action)
        if category == 'BACKUP_ARCHIVE' and current_state == 'BLOCKED':
            required_state = 'BLOCKED'
            is_satisfied = True
        else:
            is_satisfied = (current_state == required_state)

        violation_finding = None
        remediation_op = None
        if not is_satisfied:
            violation_finding = ACTION_TO_FINDING.get(required_action)
            remediation_op = ACTION_TO_REMEDIATION.get(required_action)

        verification_op = STATE_TO_VERIFICATION.get(required_state)

        return PolicyDecision(
            rule_id=rule['rule_id'],
            category=category,
            required_action=required_action,
            required_state=required_state,
            is_satisfied=is_satisfied,
            violation_finding=violation_finding,
            remediation_op=remediation_op,
            verification_op=verification_op,
            system_id=system_id,
            resource_id=resource_id,
        )

    def _eval_condition(self, condition: str, current_state: str, context: dict) -> bool:
        cond = condition.lower()

        if cond == 'always':
            return True

        if 'retention period' in cond:
            # SECURITY_AUDIT_LOG: within retention period → must RETAIN
            retention_until = context.get('retention_until')
            audit_at = context.get('audit_at')
            if retention_until and audit_at:
                return audit_at <= retention_until
            return True  # conservative: assume retained

        if 'legal hold' in cond:
            return context.get('has_legal_hold', False)

        if 'restore access can be blocked' in cond:
            # BACKUP_ARCHIVE → always apply (can always block)
            return True

        if 'still attributable' in cond:
            # ANALYTICS / PRODUCT_TELEMETRY: apply if not already anonymized
            return current_state != 'ANONYMIZED'

        if 'shared customer' in cond or 'shared' in cond:
            # SUPPORT_MESSAGE: conservative → apply REDACT
            return True

        if 'belongs only' in cond:
            # SUPPORT_ATTACHMENT: if it's a sole-subject attachment → DELETE
            # We conservatively apply this rule
            return True

        # Unknown condition → apply conservatively
        logger.warning(f"Unknown condition: '{condition}' — applying conservatively")
        return True
