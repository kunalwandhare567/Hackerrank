"""
activity.py — System activity index and data-flow / resurrection detection.
Loads system_activity.csv and provides fast identity-based lookup.
"""
import csv
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Tuple

logger = logging.getLogger(__name__)


def _parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.rstrip('Z')).replace(tzinfo=timezone.utc)
    except Exception:
        return None


@dataclass
class ActivityEvent:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass
class DataFlowRisk:
    resource_id: str
    flow_type: str          # SYNC | CONNECTOR | RESTORE | RESTORE_EXECUTED
    state: str              # ACTIVE
    evidence_id: str        # activity_XXXX or file_id
    system_id: str = 'integration_service'
    target_system: str = ''
    downstream_resource: str = ''


class ActivityIndex:
    """
    Indexes 4011 system_activity.csv rows.
    Provides:
      - find_for_identity(): events relevant to a user
      - detect_data_flow_risks(): active sync/restore risks
      - is_classified_non_deletion(): for NOT_APPLICABLE detection
      - resource_identity_links: LINK_RESOURCE_IDENTITY mappings
    """

    def __init__(self, activity_csv: Path):
        self._events: List[ActivityEvent] = []
        self._by_resource: Dict[str, List[ActivityEvent]] = defaultdict(list)
        self._non_deletion_accounts: Dict[str, str] = {}   # account_id → activity_id
        self._linked: Dict[str, Tuple[str, str]] = {}       # resource_id → (email, user_id)

        with open(activity_csv, encoding='utf-8') as f:
            for row in csv.DictReader(f):
                evt = ActivityEvent(
                    activity_id=row['activity_id'],
                    event_time=_parse_dt(row['event_time']),
                    event_type=row['event_type'],
                    source_system=row['source_system'],
                    target_system=row['target_system'],
                    resource_id=row['resource_id'],
                    reported_result=row['reported_result'],
                    details=row['details'],
                )
                self._events.append(evt)
                if evt.resource_id:
                    self._by_resource[evt.resource_id].append(evt)

                # CLASSIFY_REQUEST → non-deletion
                if evt.event_type == 'CLASSIFY_REQUEST' and 'non-deletion' in evt.details:
                    self._non_deletion_accounts[evt.resource_id] = evt.activity_id

                # LINK_RESOURCE_IDENTITY → explicit resource→identity mapping
                if evt.event_type == 'LINK_RESOURCE_IDENTITY':
                    m = re.search(r'to\s+(\S+@\S+)\s+and\s+(user_\d+)', evt.details, re.I)
                    if m:
                        email, uid = m.group(1).lower(), m.group(2)
                        self._linked[evt.resource_id] = (email, uid)

    # ── Public API ────────────────────────────────────────────────────────────

    def find_for_identity(
        self,
        all_emails: List[str],
        all_phones: List[str],
        all_hashes: List[str],
        user_id: Optional[str],
        audit_at: datetime,
    ) -> List[ActivityEvent]:
        """Return all activity events at or before audit_at that concern this identity."""
        relevant = []
        seen = set()

        for evt in self._events:
            if evt.event_time and evt.event_time > audit_at:
                continue
            if evt.activity_id in seen:
                continue
            if self._event_matches(evt, all_emails, all_phones, all_hashes, user_id):
                relevant.append(evt)
                seen.add(evt.activity_id)

        return relevant

    def detect_data_flow_risks(
        self,
        case_events: List[ActivityEvent],
        all_emails: List[str],
        user_id: Optional[str],
        audit_at: datetime,
    ) -> List[DataFlowRisk]:
        """
        Detect active data flows and restore risks from case events.
        Rules:
        - SYNC_RECORD with no subsequent DISABLE_DATA_FLOW → REPORT_ACTIVE_DATA_FLOW
        - CHECK_RESTORE_ACCESS (restore_allowed=true) with no BLOCK_RESTORE → REPORT_RESTORE_RISK
        - RESTORE_BACKUP event → REPORT_RESTORE_RISK (resurrection!)
        """
        risks: List[DataFlowRisk] = []

        # Build sets of disabled flows and blocked restores (by resource_id)
        disabled_flows = set()
        blocked_restores = set()

        for evt in case_events:
            if evt.event_type == 'DISABLE_DATA_FLOW' and evt.reported_result == 'SUCCESS':
                disabled_flows.add(evt.resource_id)
            if evt.event_type == 'BLOCK_RESTORE' and evt.reported_result == 'SUCCESS':
                blocked_restores.add(evt.resource_id)

        seen_risks: set = set()

        for evt in case_events:
            # Active sync flows
            if evt.event_type == 'SYNC_RECORD':
                # Find the data_flow resource_id for this sync (may be analytics_XXX or account_XXX)
                # Look for associated DISABLE_DATA_FLOW
                related_flow = self._find_associated_flow(evt, case_events)
                if related_flow and related_flow not in disabled_flows:
                    if related_flow not in seen_risks:
                        seen_risks.add(related_flow)
                        risks.append(DataFlowRisk(
                            resource_id=related_flow,
                            flow_type='SYNC',
                            state='ACTIVE',
                            evidence_id=f'activity_{evt.activity_id}',
                            system_id='integration_service',
                            target_system=evt.target_system,
                        ))

            # Check data flow status checks
            if evt.event_type == 'CHECK_DATA_FLOW' and 'active' in evt.details.lower():
                if evt.resource_id not in disabled_flows and evt.resource_id not in seen_risks:
                    seen_risks.add(evt.resource_id)
                    risks.append(DataFlowRisk(
                        resource_id=evt.resource_id,
                        flow_type='SYNC',
                        state='ACTIVE',
                        evidence_id=f'activity_{evt.activity_id}',
                        system_id='integration_service',
                        target_system=evt.target_system,
                    ))

            # Restore risk
            if evt.event_type == 'CHECK_RESTORE_ACCESS' and 'restore_allowed=true' in evt.details:
                if evt.resource_id not in blocked_restores and evt.resource_id not in seen_risks:
                    seen_risks.add(evt.resource_id)
                    risks.append(DataFlowRisk(
                        resource_id=evt.resource_id,
                        flow_type='RESTORE',
                        state='ACTIVE',
                        evidence_id=f'activity_{evt.activity_id}',
                        system_id='backup_service',
                    ))

            # Active RESTORE_BACKUP = resurrection
            if evt.event_type == 'RESTORE_BACKUP':
                # "Restore job repopulated downstream resource search_XXXX."
                m = re.search(r'downstream resource (\S+?)\.?$', evt.details)
                downstream = m.group(1) if m else ''
                if evt.resource_id not in seen_risks:
                    seen_risks.add(evt.resource_id)
                    risks.append(DataFlowRisk(
                        resource_id=evt.resource_id,
                        flow_type='RESTORE_EXECUTED',
                        state='ACTIVE',
                        evidence_id=f'activity_{evt.activity_id}',
                        system_id='backup_service',
                        downstream_resource=downstream,
                    ))

        return risks

    def is_non_deletion(self, resource_id: str) -> bool:
        """Check if an account resource_id was classified as a non-deletion request."""
        return resource_id in self._non_deletion_accounts

    def get_linked_identity(self, resource_id: str):
        """Return (email, user_id) if this resource was explicitly linked via LINK_RESOURCE_IDENTITY."""
        return self._linked.get(resource_id)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _event_matches(
        self,
        evt: ActivityEvent,
        all_emails: List[str],
        all_phones: List[str],
        all_hashes: List[str],
        user_id: Optional[str],
    ) -> bool:
        text = evt.details.lower()
        for em in all_emails:
            if em in text:
                return True
        if user_id and user_id in evt.details:
            return True
        # Check LINK_RESOURCE_IDENTITY
        if evt.resource_id in self._linked:
            linked_email, linked_uid = self._linked[evt.resource_id]
            if linked_email in all_emails:
                return True
            if linked_uid == user_id:
                return True
        return False

    def _find_associated_flow(self, sync_evt: ActivityEvent, case_events: List[ActivityEvent]) -> Optional[str]:
        """
        For a SYNC_RECORD event, try to find the associated data_flow resource_id.
        Look for DISABLE_DATA_FLOW or CHECK_DATA_FLOW events around the same time.
        Fallback: return the sync target resource_id.
        """
        # Look for LINK_RESOURCE_IDENTITY that links a data_flow to the same identity
        for evt in case_events:
            if evt.event_type in ('DISABLE_DATA_FLOW', 'CHECK_DATA_FLOW'):
                return evt.resource_id
        # Return the sync's own resource_id as a proxy
        # (in practice, sync events have analytics_XXXX as resource_id, but the data_flow is separate)
        return sync_evt.resource_id
