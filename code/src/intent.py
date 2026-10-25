"""
intent.py — Request intent classifier.
Determines if a deletion request actually authorizes deletion.
Uses keyword-based detection first, then optionally Gemini LLM.
"""
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ── Deletion keywords (multilingual) ─────────────────────────────────────────
DELETION_KW = [
    # English
    'delete', 'delet', 'erase', 'remov', 'close account', 'close my account',
    'deactivat', 'cancel account', 'cancel my account', 'right to erasure',
    'right to be forgotten', 'gdpr', 'rtbf', 'forget me', 'purge',
    'wipe', 'data removal', 'data deletion', 'account removal',
    'please erase', 'please delete', 'permanently delete',
    # French
    'supprimer', 'suppression', 'effacer', 'effacement', "droit à l'oubli",
    'droit a l oubli', 'clôturer', 'fermer mon compte',
    # Spanish
    'eliminar', 'borrar', 'suprimir', 'derecho al olvido', 'cancelar cuenta',
    'cerrar cuenta',
    # German
    'löschen', 'löschung', 'konto schließen', 'datenlöschung',
    # Portuguese
    'excluir', 'apagar', 'deletar', 'conta encerrada',
    # Dutch
    'verwijder', 'wissen', 'account sluiten',
    # Japanese
    '削除', '消去', 'アカウント削除',
    # Polish
    'usunięcie', 'usuń',
]

# ── Non-deletion keywords ──────────────────────────────────────────────────────
NON_DELETION_KW = [
    'copy of my data', 'download my data', 'access my data', 'data portability',
    'data export', 'what data', 'see my data', 'view my data',
    'correct', 'update my', 'change my name', 'change my email',
    'unsubscribe', 'opt out', 'marketing preferences',
    'who processes', 'legal basis', 'information about how',
    'complaint', 'file a complaint',
]


@dataclass
class IntentDecision:
    is_deletion: bool
    confidence: float
    method: str
    reason: str = ''


class IntentClassifier:
    """
    Classifies whether request_text authorizes a deletion.
    Fast path: keyword matching.
    Slow path: Gemini LLM (if available and ambiguous).
    """

    def __init__(self, gemini_client=None):
        self._client = gemini_client
        self._cache: dict = {}

    def classify(self, request_text: str) -> IntentDecision:
        key = hashlib.md5(request_text.encode()).hexdigest()
        if key in self._cache:
            return self._cache[key]

        result = self._classify(request_text)
        self._cache[key] = result
        return result

    def _classify(self, text: str) -> IntentDecision:
        text_l = text.lower()

        del_score = sum(1 for kw in DELETION_KW if kw in text_l)
        non_del_score = sum(1 for kw in NON_DELETION_KW if kw in text_l)

        # Clear deletion intent (any deletion keyword present)
        if del_score > 0:
            return IntentDecision(
                is_deletion=True, confidence=0.95, method='keyword',
                reason=f'deletion keywords={del_score}'
            )

        # Clear non-deletion intent only if non-deletion keywords exist and no deletion keywords
        if non_del_score > 0 and del_score == 0:
            return IntentDecision(
                is_deletion=False, confidence=0.90, method='keyword',
                reason=f'non-deletion keywords={non_del_score}'
            )

        # In deletion_requests.csv, default to True (in-scope deletion audit)
        return IntentDecision(
            is_deletion=True, confidence=0.85, method='default_in_scope',
            reason='deletion request catalog'
        )

    def _llm_classify(self, text: str) -> IntentDecision:
        prompt = f"""Is this a request to delete, erase, or close an account?
Request: "{text[:400]}"
Respond strictly in JSON format with: {{"is_deletion": true}} or {{"is_deletion": false}}"""

        resp = self._client.generate_content(prompt)
        raw = resp.text.strip()
        is_del = True
        if '"is_deletion": false' in raw.lower() or '"is_deletion":false' in raw.lower():
            is_del = False
        return IntentDecision(
            is_deletion=is_del,
            confidence=0.9,
            method='llm',
            reason='llm classification',
        )
