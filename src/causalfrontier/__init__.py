"""CausalFrontier public API."""

from .capsule import build_capsule, record_rehearsal, verify_capsule
from .frontier import compile_case, simulate_branch
from .ledger import append_event, create_ledger, verify_ledger
from .model import load_case, validate_case

__all__ = [
    "append_event",
    "build_capsule",
    "compile_case",
    "create_ledger",
    "load_case",
    "record_rehearsal",
    "simulate_branch",
    "validate_case",
    "verify_capsule",
    "verify_ledger",
]

__version__ = "0.1.0a1"
