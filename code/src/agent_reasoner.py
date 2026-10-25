"""
agent_reasoner.py — AI Reasoning Agent for Ambiguous Evidence & Vision.
Uses LLM to interpret complex records (multi-user bulk exports, status 404s, PNGs)
with prompt-hash caching and robust deterministic fallbacks.
"""
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class AgentEvidenceReasoner:
    """
    Intelligent evidence reasoning agent that supplements deterministic parsers.
    """

    def __init__(self, gemini_model=None):
        self.model = gemini_model
        self._cache: Dict[str, Any] = {}

    def _hash_key(self, text: str) -> str:
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    def reason_record(
        self,
        snippet: str,
        user_id: Optional[str],
        current_email: str,
        all_emails: List[str],
        file_id: str = '',
    ) -> List[Dict[str, Any]]:
        """
        Analyze whether an ambiguous evidence record proves state for this user.
        Returns a list of structured findings:
        [{'resource_id': ..., 'state': ..., 'system_id': ..., 'confidence': ...}]
        """
        if not snippet or not snippet.strip():
            return []

        # Check in-memory cache
        cache_key = self._hash_key(f"{user_id}:{current_email}:{snippet[:400]}")
        if cache_key in self._cache:
            return self._cache[cache_key]

        findings = []

        # 1. Deterministic heuristic fast-path
        heuristic_res = self._heuristic_match(snippet, user_id, current_email, all_emails)
        if heuristic_res:
            self._cache[cache_key] = heuristic_res
            return heuristic_res

        # 2. LLM reasoning if model available
        if self.model:
            try:
                findings = self._llm_reason(snippet, user_id, current_email, all_emails, file_id)
            except Exception as e:
                logger.warning(f"LLM reasoning error for {user_id}: {e}")
                findings = []

        self._cache[cache_key] = findings
        return findings

    def _heuristic_match(
        self,
        snippet: str,
        user_id: Optional[str],
        current_email: str,
        all_emails: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Fast heuristic matching for common patterns like status_code=404, profile=None.
        """
        results = []
        lower_snip = snippet.lower()

        # Check if user_id or any email is referenced
        user_matched = False
        if user_id and user_id.lower() in lower_snip:
            user_matched = True
        for em in all_emails:
            if em.lower() in lower_snip:
                user_matched = True
                break

        # If user is matched in a record containing 404 / None
        if user_matched:
            # Check for account resource
            acc_match = re.search(r'\b(account_\d+)\b', snippet)
            if acc_match:
                res_id = acc_match.group(1)
                if '404' in snippet or 'null' in lower_snip or 'not_found' in lower_snip or 'profile=none' in lower_snip:
                    results.append({
                        'resource_id': res_id,
                        'state': 'ABSENT',
                        'system_id': 'account_service',
                        'confidence': 0.95,
                    })

            # Check for audit_record (often security audit log)
            audit_match = re.search(r'\b(audit_record_\d+)\b', snippet)
            if audit_match:
                res_id = audit_match.group(1)
                results.append({
                    'resource_id': res_id,
                    'state': 'PRESENT',
                    'system_id': 'security_service',
                    'confidence': 0.95,
                })

            # Check for support message
            supp_match = re.search(r'\b(support_\d+)\b', snippet)
            if supp_match:
                res_id = supp_match.group(1)
                state = 'REDACTED' if 'redact' in lower_snip else 'PRESENT'
                results.append({
                    'resource_id': res_id,
                    'state': state,
                    'system_id': 'support_platform',
                    'confidence': 0.90,
                })

            # Check for analytics profile
            ana_match = re.search(r'\b(analytics_\d+)\b', snippet)
            if ana_match:
                res_id = ana_match.group(1)
                state = 'ANONYMIZED' if ('anon' in lower_snip or 'null' in lower_snip) else 'PRESENT'
                results.append({
                    'resource_id': res_id,
                    'state': state,
                    'system_id': 'analytics_platform',
                    'confidence': 0.90,
                })

        return results

    def _llm_reason(
        self,
        snippet: str,
        user_id: Optional[str],
        current_email: str,
        all_emails: List[str],
        file_id: str,
    ) -> List[Dict[str, Any]]:
        prompt = f"""You are an expert data privacy auditor analyzing evidence logs.
TARGET USER:
- User ID: {user_id}
- Primary Email: {current_email}
- Known Identifiers: {all_emails}

EVIDENCE RECORD ({file_id}):
\"\"\"{snippet[:1000]}\"\"\"

TASK:
Determine if this record proves the state of any data resource belonging to this target user.
Allowed states: ABSENT, PRESENT, REDACTED, ANONYMIZED, DISABLED, BLOCKED.
Respond with a JSON array ONLY:
[
  {{
    "resource_id": "account_XXXX / audit_record_XXXX / etc.",
    "system_id": "account_service / security_service / support_platform / analytics_platform / etc.",
    "state": "ABSENT / PRESENT / REDACTED / ANONYMIZED",
    "confidence": 0.9
  }}
]
If the record does not belong to the target user or is unrelated, reply with []."""

        response = self.model.generate_content(prompt)
        text = response.text.strip()

        # Extract JSON array
        m = re.search(r'\[.*\]', text, re.DOTALL)
        if m:
            data = json.loads(m.group(0))
            if isinstance(data, list):
                return data
        return []
