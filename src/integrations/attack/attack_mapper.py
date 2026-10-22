"""
MITRE ATT&CK technique matcher.

Loads the MITRE ATT&CK Enterprise STIX corpus (via the official
``mitreattack-python`` library) and matches free-text investigation
findings against technique names/descriptions using TF-IDF keyword
overlap. This is intentionally a simple bag-of-words matcher, not an
NLP/semantic model - good enough to surface likely techniques for an
analyst to confirm, not a substitute for expert judgement.

Refreshing the cached dataset
------------------------------
The Enterprise ATT&CK STIX bundle is cached locally (default:
``data/attack/enterprise-attack.json``) so the server does not need
network access on every run. To refresh it to the latest version from
MITRE, either delete the cache file (it will be re-downloaded on next
use) or call ``AttackMapper.download_dataset(cache_path, force=True)``,
e.g.:

    python -c "from src.integrations.attack.attack_mapper import AttackMapper; \
        AttackMapper.download_dataset(force=True)"
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional

from ...core.errors import IntegrationError
from ...core.logging import get_logger

logger = get_logger("sami.integrations.attack.mapper")

ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# src/integrations/attack/attack_mapper.py -> src/integrations/attack -> src/integrations -> src -> project root
_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
DEFAULT_CACHE_PATH = os.path.join(_PROJECT_ROOT, "data", "attack", "enterprise-attack.json")

# Technique name tokens are repeated this many times relative to the
# description when building the TF-IDF document, so a query that names the
# technique directly (e.g. "PowerShell") outweighs incidental overlap with
# unrelated, longer technique descriptions.
_NAME_WEIGHT = 3

_STOPWORDS = frozenset(
    """
    a an the of to in on for and or is are was were be been being with by
    from at as that this it its into over under via using use used can may
    also able allow allows which then if not no yes
    """.split()
)

_TOKEN_RE = re.compile(r"[a-zA-Z0-9]+")


def _tokenize(text: str) -> List[str]:
    return [
        word
        for word in _TOKEN_RE.findall(text.lower())
        if len(word) > 2 and word not in _STOPWORDS
    ]


class _TechniqueDoc:
    __slots__ = ("attack_id", "name", "tactics", "term_counts", "norm")

    def __init__(self, attack_id: str, name: str, tactics: List[str], term_counts: Counter):
        self.attack_id = attack_id
        self.name = name
        self.tactics = tactics
        self.term_counts = term_counts
        self.norm = 1.0  # filled in once IDF weights are known


class AttackMapper:
    """
    Matches free text against MITRE ATT&CK Enterprise techniques.

    Usage:
        mapper = AttackMapper()
        mapper.match_techniques("powershell.exe with an encoded command")
    """

    def __init__(
        self,
        cache_path: Optional[str] = None,
        auto_download: bool = True,
    ) -> None:
        """
        Args:
            cache_path: Path to the local ATT&CK Enterprise STIX JSON file.
                Defaults to ``data/attack/enterprise-attack.json`` under the
                project root.
            auto_download: If the cache file is missing, download it from
                MITRE/CTI on GitHub. If False and the cache is missing,
                raises IntegrationError.
        """
        self.cache_path = cache_path or DEFAULT_CACHE_PATH

        if not os.path.exists(self.cache_path):
            if not auto_download:
                raise IntegrationError(
                    f"ATT&CK dataset not found at {self.cache_path} and auto_download=False"
                )
            self.download_dataset(self.cache_path)

        self._idf: Dict[str, float] = {}
        self._docs: List[_TechniqueDoc] = []
        self._build_index()

    @staticmethod
    def download_dataset(
        cache_path: Optional[str] = None,
        url: str = ENTERPRISE_ATTACK_URL,
        force: bool = False,
    ) -> str:
        """
        Download the ATT&CK Enterprise STIX bundle to ``cache_path``.

        Args:
            cache_path: Destination path. Defaults to DEFAULT_CACHE_PATH.
            url: Source URL for the STIX bundle.
            force: Re-download even if the cache file already exists.

        Returns:
            The cache path the dataset was written to.

        Raises:
            IntegrationError: If the download fails.
        """
        import requests

        cache_path = cache_path or DEFAULT_CACHE_PATH
        if os.path.exists(cache_path) and not force:
            return cache_path

        try:
            logger.info(f"Downloading ATT&CK Enterprise dataset from {url}")
            response = requests.get(url, timeout=60)
            response.raise_for_status()
        except Exception as e:
            raise IntegrationError(f"Failed to download ATT&CK dataset from {url}: {e}") from e

        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "wb") as f:
            f.write(response.content)
        logger.info(f"ATT&CK Enterprise dataset cached at {cache_path}")
        return cache_path

    def _build_index(self) -> None:
        try:
            from mitreattack.stix20 import MitreAttackData
        except ImportError as e:
            raise IntegrationError(
                "mitreattack-python is not installed; add it to requirements.txt"
            ) from e

        try:
            attack_data = MitreAttackData(self.cache_path)
            techniques = attack_data.get_techniques(remove_revoked_deprecated=True)
        except Exception as e:
            raise IntegrationError(f"Failed to load ATT&CK dataset from {self.cache_path}: {e}") from e

        document_frequency: Counter = Counter()
        raw_docs: List[_TechniqueDoc] = []

        for technique in techniques:
            attack_id = attack_data.get_attack_id(technique["id"])
            if not attack_id:
                continue
            name = technique.get("name", "")
            description = technique.get("description", "")
            tactics = sorted(
                {phase.get("phase_name", "") for phase in technique.get("kill_chain_phases", [])}
            )

            weighted_text = f"{(name + ' ') * _NAME_WEIGHT}{description}"
            term_counts = Counter(_tokenize(weighted_text))
            if not term_counts:
                continue

            for term in term_counts:
                document_frequency[term] += 1

            raw_docs.append(_TechniqueDoc(attack_id, name, tactics, term_counts))

        num_docs = len(raw_docs) or 1
        self._idf = {
            term: math.log(1 + num_docs / (1 + df)) for term, df in document_frequency.items()
        }

        for doc in raw_docs:
            doc.norm = self._vector_norm(doc.term_counts)

        self._docs = raw_docs
        logger.info(f"ATT&CK matcher indexed {len(self._docs)} techniques")

    def _vector_norm(self, term_counts: Counter) -> float:
        return math.sqrt(
            sum((count * self._idf.get(term, 0.0)) ** 2 for term, count in term_counts.items())
        ) or 1.0

    def match_techniques(
        self,
        text: str,
        top_n: int = 5,
        min_score: float = 0.01,
    ) -> List[Dict[str, Any]]:
        """
        Match free text against known ATT&CK techniques.

        Args:
            text: Free-text investigation finding (e.g. process command
                lines, detection descriptions, analyst notes).
            top_n: Maximum number of matches to return.
            min_score: Minimum cosine-similarity score (0-1) for a match
                to be included.

        Returns:
            List of matches sorted by descending score, each with keys:
            technique_id, technique_name, tactics, score.
        """
        query_terms = Counter(_tokenize(text))
        if not query_terms:
            return []

        query_norm = self._vector_norm(query_terms)

        scored: List[Dict[str, Any]] = []
        for doc in self._docs:
            dot = sum(
                qcount * self._idf.get(term, 0.0) * doc.term_counts[term] * self._idf.get(term, 0.0)
                for term, qcount in query_terms.items()
                if term in doc.term_counts
            )
            if dot <= 0:
                continue
            score = dot / (query_norm * doc.norm)
            if score < min_score:
                continue
            scored.append(
                {
                    "technique_id": doc.attack_id,
                    "technique_name": doc.name,
                    "tactics": doc.tactics,
                    "score": round(score, 4),
                }
            )

        scored.sort(key=lambda m: m["score"], reverse=True)
        return scored[:top_n]
