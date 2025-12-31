from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

@dataclass
class SortParam:
    """Defines sorting parameters for a request."""
    colId: str
    sort: str # 'asc' or 'desc'

@dataclass
class TimeRangeFilter:
    """Defines a time range for filtering."""
    start: str # YYYY-MM-DD hh:mm:ss
    end: str   # YYYY-MM-DD hh:mm:ss

@dataclass
class IncidentFilters:
    """Defines filter criteria for incident searches."""
    time_range_filter: Optional[TimeRangeFilter] = None
    incident_id_filters: Optional[List[str]] = None
    other_filters: Optional[List[str]] = None
    priority_filters: Optional[List[str]] = None
    source_filters: Optional[List[str]] = None
    disposition_filters: Optional[List[str]] = None
    verdict_filters: Optional[List[str]] = None
    confidence_filters: Optional[List[str]] = None

@dataclass
class MessageFilters(IncidentFilters):
    """Defines filter criteria for message searches. Inherits from IncidentFilters."""
    message_id_filters: Optional[List[str]] = None
    recipient_address_filters: Optional[List[str]] = None
    sender_address_filters: Optional[List[str]] = None
    subject_filters: Optional[List[str]] = None
    status_filters: Optional[List[str]] = None
    quarantine_filters: Optional[List[str]] = None
    tap_threat_filters: Optional[List[str]] = None
    tap_threat_type_filters: Optional[List[str]] = None
