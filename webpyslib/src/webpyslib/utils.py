"""
webpyslib.utils
Utility functions for validation.
"""

import re
import ipaddress


def is_valid_email(email: str) -> bool:
    """Return True if the email format is valid."""
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_ipv4(ip: str) -> bool:
    """Return True if the string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_url(url: str) -> bool:
    """Return True if the URL starts with http:// or https://."""
    pattern = r"^https?://[^\s/$.?#].[^\s]*$"
    return bool(re.match(pattern, url))


def is_strong_password(password: str) -> bool:
    """
    Check if a password is strong.

    Requirements:
    - At least 8 characters
    - One uppercase letter
    - One lowercase letter
    - One digit
    - One special character
    """
    pattern = (
        r"^(?=.*[a-z])"
        r"(?=.*[A-Z])"
        r"(?=.*\d)"
        r"(?=.*[@$!%*?&])"
        r"[A-Za-z\d@$!%*?&]{8,}$"
    )
    return bool(re.match(pattern, password))