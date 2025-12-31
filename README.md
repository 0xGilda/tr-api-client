# Proofpoint CTR API Python Client

A Python client library for interacting with the Proofpoint Threat Protection API(Specifically the Cloud Threat Response related endpoints).

This library handles authentication via client credentials (Client ID and Client Secret) and provides user-friendly methods for all documented API endpoints as of 31/12/2025 for interacting with the CTR Workflows, Incidents, and Messages APIs.

## Installation

This project now uses plain `pip`.

1.  (Recommended) Create and activate a virtual environment using `python -m venv .venv`.
2.  Install the package and its dependencies:
    ```bash
    pip install -e .
    ```

## Usage

## Authentication

Before using this library, you will need to generate a Client ID and Client Secret from the Proofpoint Admin Portal. See the [API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management) documentation.

The client will automatically:
- Obtain an access token using your client ID and secret
- Refresh the token when it expires (tokens are valid for 1 hour)
- Add the Bearer token to all API requests

## Usage

### 1. Initialization

First, import and instantiate the client with your API credentials, which can be obtained from the (Proofpoint Admin Portal)[https://admin.proofpoint.com/apiKeyManagement].

```python
import os
from proofpoint_client.client import ProofpointApiClient
from proofpoint_client.exceptions import ProofpointApiException

# It's recommended to use environment variables for credentials
CLIENT_ID = os.environ.get("PROOFPOINT_CLIENT_ID")
CLIENT_SECRET = os.environ.get("PROOFPOINT_CLIENT_SECRET")

try:
    client = ProofpointApiClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    print("Successfully authenticated!")
except ProofpointApiException as e:
    print(f"Authentication failed: {e}")
```

### 2. Calling API Endpoints

Once instantiated, you can call methods corresponding to the API endpoints.

#### Example: Get all enabled Incident Workflows

```python
try:
    incident_workflows = client.get_workflows(enabled=True, workflow_type="incident")
    for wf in incident_workflows:
        print(f"- ID: {wf['id']}, Name: {wf['name']}")
except ProofpointApiException as e:
    print(f"Error fetching workflows: {e}")
```

#### Example: Download a Message

```python
# Assume you have a message_id from a previous call
message_id_to_download = "598ba766-5c38-4ca6-be25-565faae3a3b8" 

try:
    print(f"Downloading MIME for message {message_id_to_download}...")
    eml_content = client.download_message_mime(message_id=message_id_to_download)
    
    # Save the content to a file
    file_name = f"{message_id_to_download}.eml"
    with open(file_name, "wb") as f:
        f.write(eml_content)
    print(f"Message saved to {file_name}")

except ProofpointApiException as e:
    print(f"Error downloading message: {e}")
```

### Error Handling

The client raises specific exceptions for different types of errors, all inheriting from `ProofpointApiException`.

- `ProofpointApiAuthError`: For 401/403 errors.
- `ProofpointApiBadRequestError`: For 400 errors.
- `ProofpointApiRateLimitError`: For 429 errors.
- `ProofpointApiException`: For all other API and request errors.

## API Reference

### Client Initialization

```python
ProofpointApiClient(
    client_id: str,
    client_secret: str,
    base_url: str = "https://threatprotection-api.proofpoint.com",
    token_url: str = "https://auth.proofpoint.com/v1/token"
)
```

### Workflows

- `get_workflows(enabled: Optional[bool] = None, workflow_type: Optional[str] = None)` - Get configured workflows
- `run_workflow(workflow_id: str, target_ids: List[str])` - Execute a workflow
- `get_workflow_run_status(run_id: str)` - Check workflow execution status

### Incidents

- `search_incidents(filters: Optional[IncidentFilters] = None, start_row: int = 0, end_row: int = 200, sort_params: Optional[List[SortParam]] = None)` - Search for incidents
- `get_incident_count(filters: IncidentFilters)` - Get count of matching incidents
- `get_incident_details(incident_id: str)` - Get details for a single incident
- `get_incident_with_message_details(incident_id: str, start_row: int = 0, end_row: int = 100, sort_params: Optional[List[SortParam]] = None)` - Get incident with associated messages

### Messages

- `search_messages(filters: Optional[MessageFilters] = None, start_row: int = 0, end_row: int = 100, sort_params: Optional[List[SortParam]] = None)` - Search for messages
- `get_message_details(message_id: str)` - Get details for a single message
- `fetch_message_body(message_id: str)` - Initiate message body fetch from mailbox
- `get_message_fetch_status(message_id: str)` - Check message fetch status
- `download_message_mime(message_id: str)` - Download message as .EML file

## License

Unlicense

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
