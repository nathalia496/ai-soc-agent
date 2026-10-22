"""
LLM-callable tools for MITRE ATT&CK technique mapping.

These functions wrap AttackMapper and provide LLM-friendly error handling
and return values, following the same pattern as tools_cti.py / tools_edr.py.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..core.errors import IntegrationError
from ..integrations.attack.attack_mapper import AttackMapper


def map_to_attack(
    text: str,
    mapper: Optional[AttackMapper] = None,
    top_n: int = 5,
) -> Dict[str, Any]:
    """
    Map free-text investigation findings to MITRE ATT&CK techniques.

    Tool schema:
    - name: map_to_attack
    - description: Match investigation findings (process behavior, detection
      descriptions, analyst notes) against MITRE ATT&CK Enterprise techniques
      to help identify likely tactics/techniques involved.
    - parameters:
      - text (str, required): Free text describing the observed behavior.
      - top_n (int, optional): Maximum number of techniques to return.

    Args:
        text: Free text describing the observed behavior.
        mapper: AttackMapper instance.
        top_n: Maximum number of techniques to return.

    Returns:
        Dictionary containing matched techniques.

    Raises:
        IntegrationError: If no mapper is provided or matching fails.
    """
    if mapper is None:
        raise IntegrationError("No ATT&CK mapper provided")

    if not text or not text.strip():
        raise IntegrationError("No text provided to match against ATT&CK techniques")

    try:
        matches = mapper.match_techniques(text, top_n=top_n)
        return {
            "success": True,
            "text": text,
            "matches": matches,
            "match_count": len(matches),
        }
    except IntegrationError:
        raise
    except Exception as e:
        raise IntegrationError(f"Failed to map text to ATT&CK techniques: {str(e)}") from e
