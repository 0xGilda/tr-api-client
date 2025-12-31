class ProofpointApiException(Exception):
    """Base exception for API-related errors."""
    def __init__(self, message: str, status_code: int = None, response_text: str = None):
        self.status_code = status_code
        self.response_text = response_text
        full_message = f"[{status_code}] {message}"
        if response_text:
            full_message += f"\nResponse: {response_text}"
        super().__init__(full_message)

class ProofpointApiAuthError(ProofpointApiException):
    """Raised for authentication errors (401, 403)."""
    pass

class ProofpointApiBadRequestError(ProofpointApiException):
    """Raised for client-side errors (400)."""
    pass

class ProofpointApiRateLimitError(ProofpointApiException):
    """Raised when the rate limit is exceeded (429)."""
    pass
