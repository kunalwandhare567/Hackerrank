"""
Ghost Data Still Exists — Complete Deletion Audit Agent
HackerRank Orchestrate October 2026

Identity Resolution Engine
"""
import csv
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


def parse_dt(s: str) -> Optional[datetime]:
    """Parse ISO-8601 datetime string to datetime (UTC)."""
    if not s or s.strip() == '':
        return None
    s = s.strip().rstrip('Z')
    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except Exception:
        return None


@dataclass
class UserIdentity:
    user_id: str
    name: str
    current_email: str
    current_phone: str
    current_hash: str
    updated_at: Optional[datetime]


@dataclass
class IdentityResolution:
    user_id: Optional[str]
    name: str
    all_emails: List[str]          # lowercase, current + historical
    all_phones: List[str]
    all_hashes: List[str]
    match_type: str                 # CURRENT_EMAIL | HISTORICAL_EMAIL | HASH | UNRESOLVED
    audit_ids: List[str]            # audit_log IDs that prove the history link


class IdentityResolver:
    """
    Resolves a case email to a complete identity using:
    1. Current user_identities.csv (exact email match)
    2. user_audit_log.csv old_value fields (historical emails)
    3. SHA-256 hash matching as fallback
    """

    def __init__(self, identities_path: Path, audit_log_path: Path):
        # Current identities
        self._by_email: Dict[str, UserIdentity] = {}
        self._by_user_id: Dict[str, UserIdentity] = {}

        with open(identities_path, encoding='utf-8') as f:
            for row in csv.DictReader(f):
                uid = UserIdentity(
                    user_id=row['user_id'],
                    name=row['name'],
                    current_email=row['email'].strip().lower(),
                    current_phone=row['phone'].strip(),
                    current_hash=row['email_hash'].strip(),
                    updated_at=parse_dt(row['updated_at']),
                )
                self._by_email[uid.current_email] = uid
                self._by_user_id[uid.user_id] = uid

        # Historical changes: field_name ∈ {email, phone, email_hash}
        # key = old_value_lower → (user_id, audit_id)
        self._hist_email: Dict[str, Tuple[str, str]] = {}   # old_email → (user_id, audit_id)
        self._hist_phone: Dict[str, Tuple[str, str]] = {}
        self._hist_hash: Dict[str, Tuple[str, str]] = {}
        # user_id → list of audit_ids that proved historical link
        self._audit_ids_per_user: Dict[str, List[str]] = {}

        with open(audit_log_path, encoding='utf-8') as f:
            for row in csv.DictReader(f):
                uid_ref = row['user_id']
                field = row['field_name']
                old_val = row['old_value'].strip()
                audit_id = row['audit_id']

                if not old_val:
                    continue

                if field == 'email':
                    self._hist_email[old_val.lower()] = (uid_ref, audit_id)
                elif field == 'phone':
                    self._hist_phone[old_val] = (uid_ref, audit_id)
                elif field == 'email_hash':
                    self._hist_hash[old_val] = (uid_ref, audit_id)

                self._audit_ids_per_user.setdefault(uid_ref, [])
                if audit_id not in self._audit_ids_per_user[uid_ref]:
                    self._audit_ids_per_user[uid_ref].append(audit_id)

    def resolve(self, case_email: str) -> IdentityResolution:
        email_lower = case_email.strip().lower()

        # 1. Current email match
        if email_lower in self._by_email:
            uid = self._by_email[email_lower]
            return self._build(uid, 'CURRENT_EMAIL')

        # 2. Historical email match
        if email_lower in self._hist_email:
            user_id, audit_id = self._hist_email[email_lower]
            if user_id in self._by_user_id:
                uid = self._by_user_id[user_id]
                return self._build(uid, 'HISTORICAL_EMAIL')

        # 3. Hash match: compute SHA-256 of the case email
        computed_hash = hashlib.sha256(email_lower.encode()).hexdigest()
        if computed_hash in self._hist_hash:
            user_id, audit_id = self._hist_hash[computed_hash]
            if user_id in self._by_user_id:
                uid = self._by_user_id[user_id]
                return self._build(uid, 'HISTORICAL_HASH')
        # Also check current identities by hash
        for uid in self._by_email.values():
            if uid.current_hash == computed_hash:
                return self._build(uid, 'CURRENT_HASH')

        # 4. Unresolved
        return IdentityResolution(
            user_id=None,
            name='',
            all_emails=[email_lower],
            all_phones=[],
            all_hashes=[computed_hash],
            match_type='UNRESOLVED',
            audit_ids=[],
        )

    def _build(self, uid: UserIdentity, match_type: str) -> IdentityResolution:
        """Collect ALL known identifiers for this user."""
        all_emails = [uid.current_email]
        all_phones = [uid.current_phone]
        all_hashes = [uid.current_hash]

        # Historical emails
        for old_email, (user_id, _) in self._hist_email.items():
            if user_id == uid.user_id and old_email not in all_emails:
                all_emails.append(old_email)

        # Historical phones
        for old_phone, (user_id, _) in self._hist_phone.items():
            if user_id == uid.user_id and old_phone not in all_phones:
                all_phones.append(old_phone)

        # Historical hashes
        for old_hash, (user_id, _) in self._hist_hash.items():
            if user_id == uid.user_id and old_hash not in all_hashes:
                all_hashes.append(old_hash)

        audit_ids = self._audit_ids_per_user.get(uid.user_id, [])

        return IdentityResolution(
            user_id=uid.user_id,
            name=uid.name,
            all_emails=all_emails,
            all_phones=all_phones,
            all_hashes=all_hashes,
            match_type=match_type,
            audit_ids=audit_ids,
        )
