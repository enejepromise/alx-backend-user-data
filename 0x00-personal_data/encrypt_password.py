#!/usr/bin/env python3
"""
String (password) hash module
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """returns a salted, hashed password"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """determines if provided password matches hashed password"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

