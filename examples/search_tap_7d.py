import os
from datetime import datetime, timedelta, timezone

from proofpoint_client import ProofpointApiClient
from proofpoint_client import ProofpointApiException
from proofpoint_client.models import IncidentFilters, TimeRangeFilter, SortParam

client_id = os.environ.get("PROOFPOINT_CLIENT_ID")
client_secret = os.environ.get("PROOFPOINT_CLIENT_SECRET")

if not client_id or not client_secret:
    raise ValueError("Set PROOFPOINT_CLIENT_ID and PROOFPOINT_CLIENT_SECRET before running this example.")

client = ProofpointApiClient(
    client_id=client_id,
    client_secret=client_secret
)
# Define search criteria
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=7)

filters = IncidentFilters(
    source_filters=["tap"],
    time_range_filter=TimeRangeFilter(
        start=start_time.strftime("%Y-%m-%d %H:%M:%S"),
        end=end_time.strftime("%Y-%m-%d %H:%M:%S")
    )
)

sort = [SortParam(colId="createdAt", sort="desc")]

try:
    # Get the total count first
    count = client.get_incident_count(filters=filters)
    print(f"Found {count} matching incidents.")

    # Fetch the first page of results
    if count > 0:
        response = client.search_incidents(filters=filters, sort_params=sort, end_row=5)
        print("\nFirst 5 incidents:")
        for incident in response.get('incidents', []):
            print(f"  - INC-{incident['displayId']}: {incident['title']}")

except ProofpointApiException as e:
    print(f"Error searching for incidents: {e}")
