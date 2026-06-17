"""Audit agent for the Bead challenge.

Each control is a plug-in with three stages: EXTRACT (perception) ->
EVALUATE (deterministic rules) -> EMIT (schema-validated JSON). The LLM is
used for perception only; every pass/fail decision lives in deterministic
code so that conclusions are consistent, reproducible, and auditable.
"""

__version__ = "0.1.0"
