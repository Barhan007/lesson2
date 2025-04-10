import datetime
import bcrypt
from enum import Enum

class Role(Enum):
    """Роли пользователей"""
    USER = "user"
    ADMIN = "admin"

class User:
    """Сущность пользователя без ответственности за баланс"""
    def __init__(self, user_id: int, username: str, password: str, role: Role = Role.USER):
        self.user_id = user_id
        self.username = username
        self._hashed_password = self._hash_password(password)
        self.role = role
        self.created_at = datetime.now()
    
    @staticmethod
    def _hash_password(password: str) -> bytes:
        """Хеширование пароля с помощью bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    def verify_password(self, password: str) -> bool:
        """Проверка пароля"""
        return bcrypt.checkpw(password.encode('utf-8'), self._hashed_password)
    
    def __str__(self):
        return f"User(id={self.user_id}, username={self.username}, role={self.role.value})"

class Admin(User):
    """Администратор системы"""
    def __init__(self, user_id: int, username: str, password: str):
        super().__init__(user_id, username, password, Role.ADMIN)
