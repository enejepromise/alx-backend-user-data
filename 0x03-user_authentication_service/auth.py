#!/usr/bin/env python3
"""Authentication module
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


def _hash_password(password: str) -> bytes:
    """hashes a password"""
    if not password:
        return None
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def _generate_uuid() -> str:
    """Generates a uuid"""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initiator"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user"""
        if not email or not password:
            return None

        try:
            self._db.find_user_by(email=email)

        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Verify password"""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                password.encode('utf-8'),
                user.hashed_password
            )

        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Generates a user's session id"""
        try:
            user = self._db.find_user_by(email=email)
            sess_id = _generate_uuid()

            self._db.update_user(user.id, session_id=sess_id)
            return sess_id

        except NoResultFound:
            pass

    def get_user_from_session_id(self, session_id: str) -> User:
        """Retrieve a user via session id"""
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user

        except NoResultFound:
            return None

    def destroy_session(self, user_id: int):
        """Removes a user's session"""
        if user_id is None:
            return None

        self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Retrieve password reset token"""
        if not email:
            raise ValueError

        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)

            return reset_token

        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password"""
        if not reset_token:
            raise ValueError
        try:
            user = self._db.find_user_by(reset_token=reset_token)

            if not user:
                raise ValueError

            hashed_password = _hash_password(password)

            self._db.update_user(
                user.id,
                hashed_password=hashed_password,
                reset_token=None
            )

            return None

        except NoResultFound:
            raise ValueError
