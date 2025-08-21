import bcrypt

def get_password_hashing(password: str) -> str:
    """
    Хэширование пароля с безопасным логированием

    params password (str): Пароль для хэширования
    return: Захэшированный пароль
    """
    try:
        salt = bcrypt.gensalt()
        password_hashing = bcrypt.hashpw(
            password=password.encode("utf-8"),
            salt=salt
        )
        return password_hashing.decode("utf-8")
    except Exception as e:
        raise


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет соответствие введенного пароля и хешированного.

    param plain_password: Введенный пароль
    param hashed_password: Захэшированный пароль

    return: Результат проверки пароля
    """
    # Генерируем уникальный идентификатор для трекинга операции
    try:
        result = bcrypt.checkpw(plain_password.encode(
            'utf-8'), hashed_password.encode('utf-8'))
        return result
    except Exception as e:
        raise
