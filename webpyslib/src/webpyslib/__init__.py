"""
WebPyXLib
A Python utility library.
"""

__version__ = "3.0.1"
__author__ = "Pugazhenthi J"

from .core import add, subtract, multiply, divide
from .validator import TargetValidator
from webpyslib import TargetValidator
from .utils import (
    is_valid_email,
    is_valid_ipv4,
    is_valid_url,
    is_strong_password,
)