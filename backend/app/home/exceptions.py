from app.exceptions import DefaultExceptions


class HomeExceptions(DefaultExceptions):
    def __init__(message, status_code=500):
        super().__init__(message=message, status_code=status_code)