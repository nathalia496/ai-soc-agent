"""
MITRE ATT&CK integration.

Exposes ``AttackMapper``, which matches free-text investigation findings
against MITRE ATT&CK Enterprise techniques using keyword/TF-IDF overlap.
"""

from .attack_mapper import AttackMapper

__all__ = ["AttackMapper"]
