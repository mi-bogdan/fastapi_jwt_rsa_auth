class ApplicationException(Exception):
    """Базовое исключение для ошибок приложения."""
    pass


class UniqueError(ApplicationException):
    """Исключение, возникающее при попытке создать с уже существующим полем."""
    pass


class NotNullConstraintViolationException(ApplicationException):
    """Исключение, возникающее при попытке создать запрос с пустым значением."""
    pass


class DatabaseException(ApplicationException):
    """Общее исключение для ошибок базы данных."""
    pass


class NotFoundException(ApplicationException):
    """Исключение, возникающее когда данные не были найдены."""
    pass


class TokenValidationsException(ApplicationException):
    """Исключение при проблемах с валидацией токена"""
    pass

class NotAuthenticatedException(ApplicationException):
    """Исключение при Authenticated"""
    pass


