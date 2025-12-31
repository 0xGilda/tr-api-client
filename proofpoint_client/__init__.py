"""
Proofpoint Threat Protection API Python Client

A Python client library for interacting with the Proofpoint Threat Protection API.
Handles OAuth2 authentication and provides user-friendly methods for all documented
API endpoints, including Workflows, Incidents, and Messages.
"""

from .client import ProofpointApiClient
from .exceptions import (
    ProofpointApiException,
    ProofpointApiAuthError,
    ProofpointApiBadRequestError,
    ProofpointApiRateLimitError
)
from .models import (
    SortParam,
    TimeRangeFilter,
    IncidentFilters,
    MessageFilters
)

__version__ = "0.1.0"
__all__ = [
    "ProofpointApiClient",
    "ProofpointApiException",
    "ProofpointApiAuthError",
    "ProofpointApiBadRequestError",
    "ProofpointApiRateLimitError",
    "SortParam",
    "TimeRangeFilter",
    "IncidentFilters",
    "MessageFilters",
]
