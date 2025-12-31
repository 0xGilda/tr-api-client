import requests
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timedelta
from .exceptions import (
    ProofpointApiException,
    ProofpointApiAuthError,
    ProofpointApiBadRequestError,
    ProofpointApiRateLimitError
)
from .models import SortParam, IncidentFilters, MessageFilters

# Helper to remove None values from a dict, useful for cleaning up filter objects
def asdict_factory(data):
    def convert_value(obj):
        if isinstance(obj, list):
            return [convert_value(i) for i in obj]
        if hasattr(obj, "__dataclass_fields__"):
            return {k: convert_value(v) for k, v in obj.__dict__.items() if v is not None}
        return obj
    return {k: convert_value(v) for k, v in data if v is not None}


class ProofpointApiClient:
    """
    A client for interacting with the Proofpoint Threat Protection API.
    
    Handles authentication and provides methods for all documented endpoints.
    """
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://threatprotection-api.proofpoint.com",
        token_url: str = "https://auth.proofpoint.com/v1/token"
    ):
        """
        Initializes the API client and sets up authentication.

        Args:
            client_id: Your Proofpoint API client ID (key).
            client_secret: Your Proofpoint API client secret.
            base_url: The base URL for the Threat Protection API.
            token_url: The URL for obtaining the authentication token.
        """
        self.base_url = base_url
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Token management
        self._access_token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        
        # Create a session for making requests
        self.session = requests.Session()
        
        # Get initial token
        self._refresh_token()

    def _refresh_token(self):
        """
        Obtains a new access token from the Proofpoint authentication service.
        Tokens are valid for 1 hour.
        
        Raises:
            ProofpointApiAuthError: If authentication fails.
        """
        try:
            response = requests.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if response.status_code != 200:
                raise ProofpointApiAuthError(
                    "Failed to obtain access token",
                    response.status_code,
                    response.text
                )
            
            token_data = response.json()
            self._access_token = token_data["access_token"]
            # Set expiry with a 5-minute buffer to avoid edge cases
            expires_in = token_data.get("expires_in", 3600)
            self._token_expiry = datetime.utcnow() + timedelta(seconds=expires_in - 300)
            
        except requests.exceptions.RequestException as e:
            raise ProofpointApiException(f"Failed to obtain access token: {e}")
    
    def _ensure_valid_token(self):
        """Ensures the access token is valid, refreshing if necessary."""
        if not self._access_token or not self._token_expiry:
            self._refresh_token()
        elif datetime.utcnow() >= self._token_expiry:
            self._refresh_token()

    def _request(
        self,
        method: str,
        endpoint: str,
        return_json: bool = True,
        **kwargs
    ) -> Union[Dict, bytes]:
        """
        Internal method to make requests to the API.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: API endpoint path.
            return_json: If True, parses response as JSON. If False, returns raw bytes.
            **kwargs: Additional arguments to pass to the requests session method.

        Returns:
            The JSON response as a dictionary or raw bytes.

        Raises:
            ProofpointApiException: For general API errors.
            ProofpointApiAuthError: For 401 or 403 errors.
            ProofpointApiBadRequestError: For 400 errors.
            ProofpointApiRateLimitError: For 429 errors.
        """
        # Ensure we have a valid token
        self._ensure_valid_token()
        
        url = f"{self.base_url}{endpoint}"
        
        # Add Authorization header
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._access_token}"
        
        try:
            response = self.session.request(method, url, headers=headers, **kwargs)
            
            if 400 <= response.status_code < 600:
                self._handle_error(response)

            if return_json:
                return response.json() if response.text else {}
            return response.content
        
        except requests.exceptions.RequestException as e:
            raise ProofpointApiException(f"Request failed: {e}")

    def _handle_error(self, response: requests.Response):
        """Maps HTTP error codes to specific exceptions."""
        try:
            error_data = response.json()
            message = error_data.get('errorMessage', response.text)
        except ValueError:
            message = response.text
            
        if response.status_code == 400:
            raise ProofpointApiBadRequestError(message, response.status_code, response.text)
        elif response.status_code in [401, 403]:
            raise ProofpointApiAuthError(message, response.status_code, response.text)
        elif response.status_code == 429:
            raise ProofpointApiRateLimitError(message, response.status_code, response.text)
        else:
            raise ProofpointApiException(
                f"An unknown error occurred: {message}",
                response.status_code,
                response.text
            )
            
    # --- Workflows Endpoints ---

    def get_workflows(
        self, 
        enabled: Optional[bool] = None, 
        workflow_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves a list of configured manual workflows.

        Args:
            enabled: If provided, filters workflows by their enabled status.
            workflow_type: If provided, filters by type ('message' or 'incident').

        Returns:
            A list of workflow dictionaries.
        """
        params = {}
        if enabled is not None:
            params['enabled'] = str(enabled).lower()
        if workflow_type:
            params['type'] = workflow_type
            
        return self._request("GET", "/api/v1/tric/workflows", params=params)

    def run_workflow(self, workflow_id: str, target_ids: List[str]) -> Dict[str, Any]:
        """
        Triggers a specific workflow on a set of target entities.

        Args:
            workflow_id: The ID of the workflow to run.
            target_ids: A list of incident or message IDs to run the workflow on.

        Returns:
            A dictionary containing the status of the triggered workflow run.
        """
        payload = {"targetIds": target_ids}
        return self._request("POST", f"/api/v1/tric/workflows/{workflow_id}/run", json=payload)

    def get_workflow_run_status(self, run_id: str) -> Dict[str, Any]:
        """
        Checks the status of a previously triggered workflow run.

        Args:
            run_id: The ID of the workflow run to check.

        Returns:
            A dictionary containing the current status of the workflow run.
        """
        return self._request("GET", f"/api/v1/tric/workflows/run/{run_id}")
    
    # --- Incidents Endpoints ---

    def search_incidents(
        self,
        filters: Optional[IncidentFilters] = None,
        start_row: int = 0,
        end_row: int = 200,
        sort_params: Optional[List[SortParam]] = None
    ) -> Dict[str, Any]:
        """
        Searches for incidents based on filter criteria.

        Args:
            filters: An IncidentFilters object with criteria.
            start_row: Pagination start row.
            end_row: Pagination end row.
            sort_params: A list of SortParam objects for ordering results.

        Returns:
            A dictionary containing the search results and pagination info.
        """
        payload = {
            "startRow": start_row,
            "endRow": end_row
        }
        if filters:
            payload["filters"] = asdict_factory(filters.__dict__.items())
        if sort_params:
            payload["sortParams"] = [p.__dict__ for p in sort_params]
        
        return self._request("POST", "/api/v1/tric/incidents", json=payload)
    
    def get_incident_count(self, filters: IncidentFilters) -> int:
        """
        Gets the count of incidents matching the given filters.

        Args:
            filters: An IncidentFilters object with criteria.
        
        Returns:
            The total number of matching incidents.
        """
        payload = {"filters": asdict_factory(filters.__dict__.items())}
        return self._request("POST", "/api/v1/tric/incidents/count", json=payload)
        
    def get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        """
        Retrieves detailed information for a single incident.

        Args:
            incident_id: The UUID of the incident.

        Returns:
            A dictionary containing the incident's details.
        """
        return self._request("GET", f"/api/v1/tric/incidents/{incident_id}")

    def get_incident_with_message_details(
        self,
        incident_id: str,
        start_row: int = 0,
        end_row: int = 100,
        sort_params: Optional[List[SortParam]] = None
    ) -> Dict[str, Any]:
        """
        Retrieves incident details along with its associated messages.

        Args:
            incident_id: The UUID of the incident.
            start_row: Pagination start row for messages.
            end_row: Pagination end row for messages.
            sort_params: Sorting for the list of messages.

        Returns:
            A dictionary containing incident details and a list of messages.
        """
        payload = {
            "startRow": start_row,
            "endRow": end_row
        }
        if sort_params:
             payload["sortParams"] = [p.__dict__ for p in sort_params]
             
        return self._request("POST", f"/api/v1/tric/incidents/{incident_id}/messages", json=payload)
    
    def create_incident(
        self,
        title: str,
        description: str,
        priority: str
    ) -> Dict[str, Any]:
        """
        Creates a new incident manually via the API.

        Args:
            title: The title of the incident.
            description: A description of the incident.
            priority: The priority level (e.g., 'low', 'medium', 'high').

        Returns:
            A dictionary containing the created incident's id, createdAt, and displayId.
        """
        payload = {
            "title": title,
            "description": description,
            "priority": priority
        }
        return self._request("POST", "/api/v1/tric/incidents/createIncident", json=payload)
    
    def upload_message(
        self,
        incident_id: str,
        rfc_message_id: str,
        recipient_addresses: List[str],
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        disposition: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Uploads a message to an existing incident.

        Args:
            incident_id: The UUID of the incident to attach the message to.
            rfc_message_id: The RFC message ID (must include angular brackets, e.g., <message-id>).
            recipient_addresses: List of recipient email addresses (up to 10,000).
            sender: Optional sender email address.
            subject: Optional email subject.
            disposition: Optional disposition value.

        Returns:
            A dictionary containing rfcMessageId, incident_id, incidentDisplayId, and uploadedRecipientsCount.
        """
        message = {
            "rfcMessageId": rfc_message_id,
            "recipient_addresses": recipient_addresses
        }
        if sender:
            message["sender"] = sender
        if subject:
            message["subject"] = subject
        if disposition:
            message["disposition"] = disposition
        
        payload = {
            "incident_id": incident_id,
            "message": message
        }
        return self._request("POST", "/api/v1/tric/incidents/uploadMessage", json=payload)
        
    # --- Messages Endpoints ---
    
    def search_messages(
        self,
        filters: Optional[MessageFilters] = None,
        start_row: int = 0,
        end_row: int = 100,
        sort_params: Optional[List[SortParam]] = None
    ) -> Dict[str, Any]:
        """
        Searches for messages based on filter criteria.

        Args:
            filters: A MessageFilters object with criteria.
            start_row: Pagination start row.
            end_row: Pagination end row (max 100).
            sort_params: A list of SortParam objects for ordering results.

        Returns:
            A dictionary containing the search results and pagination info.
        """
        payload = {
            "startRow": start_row,
            "endRow": end_row
        }
        if filters:
            payload["filters"] = asdict_factory(filters.__dict__.items())
        if sort_params:
            payload["sortParams"] = [p.__dict__ for p in sort_params]
        
        return self._request("POST", "/api/v1/tric/messages", json=payload)
        
    def get_message_details(self, message_id: str) -> Dict[str, Any]:
        """
        Retrieves detailed information for a single message.

        Args:
            message_id: The UUID of the message.

        Returns:
            A dictionary containing the message's details.
        """
        return self._request("GET", f"/api/v1/tric/messages/{message_id}")
        
    def fetch_message_body(self, message_id: str) -> Dict[str, Any]:
        """
        Initiates a request to fetch a message body from the user's mailbox.

        Args:
            message_id: The UUID of the message.

        Returns:
            A dictionary indicating the fetch operation has been initiated.
        """
        return self._request("GET", f"/api/v1/tric/messages/{message_id}/fetch")
        
    def get_message_fetch_status(self, message_id: str) -> Dict[str, Any]:
        """
        Checks the status of a message body fetch operation.

        Args:
            message_id: The UUID of the message.

        Returns:
            A dictionary with the current status of the fetch operation.
        """
        return self._request("GET", f"/api/v1/tric/messages/{message_id}/fetchStatus")
        
    def download_message_mime(self, message_id: str) -> bytes:
        """
        Downloads the full MIME content of a message as an .EML file.

        Args:
            message_id: The UUID of the message.

        Returns:
            The raw bytes of the .EML file content.
        """
        return self._request("GET", f"/api/v1/tric/messages/{message_id}/download", return_json=False)
