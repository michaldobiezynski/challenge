"""Control registry: maps a control id to its assess function."""

from __future__ import annotations

from . import independent_code_review as _icr
from . import user_access_review as _uar
from .base import detect_control

REGISTRY = {
    _uar.CONTROL_ID: _uar.assess,
    _icr.CONTROL_ID: _icr.assess,
}

__all__ = ["REGISTRY", "detect_control"]
