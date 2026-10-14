"""Application exceptions."""

class AppException(Exception):
    """Base application exception."""
    def __init__(self, message: str, code: str = None, status_code: int = 400):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(message)

class NotFoundException(AppException):
    """Resource not found."""
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status_code=404)

class ConflictException(AppException):
    """Resource already exists."""
    def __init__(self, message: str = "Resource already exists"):
        super().__init__(message, status_code=409)