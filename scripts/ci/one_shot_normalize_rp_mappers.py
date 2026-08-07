#!/usr/bin/env python3
"""Apply the reviewed RP mapper-observation normalization patch once."""
from __future__ import annotations

from pathlib import Path


STATE_PATH = Path("services/account_unification/app/relying_party_state.py")


HELPERS = r'''
_OBSERVED_MAPPER_FIELDS: Final = frozenset(
    {"name", "protocol", "protocolMapper", "consentRequired", "config"}
)
_OBSERVED_CLAIM_RANKS: Final = {"role": 1, "org": 2, "workspace": 3}


def _observed_mapper_rank(mapper: dict) -> int | None:
    """Return the canonical rank for one known live mapper identity."""
    mapper_type = mapper.get("protocolMapper")
    if mapper_type == "oidc-audience-mapper":
        return 0
    if mapper_type != "oidc-hardcoded-claim-mapper":
        return None
    config = mapper.get("config")
    if not isinstance(config, dict):
        return None
    claim_name = config.get("claim.name")
    return _OBSERVED_CLAIM_RANKS.get(claim_name)


def _normalized_observed_mappers(
    value: object,
    registration: RelyingPartyRegistration,
) -> list[dict] | None:
    """Normalize safe Keycloak mapper output or return ``None`` on drift."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 4:
        return None

    ranked_mappers: list[tuple[int, dict]] = []
    seen_ranks: set[int] = set()
    for raw_mapper in value:
        if not isinstance(raw_mapper, dict):
            return None
        if any(not isinstance(key, str) for key in raw_mapper):
            return None
        mapper = dict(raw_mapper)
        mapper_id = mapper.pop("id", None)
        if mapper_id is not None and (
            not isinstance(mapper_id, str) or not mapper_id
        ):
            return None
        if set(mapper) != _OBSERVED_MAPPER_FIELDS:
            return None
        config = mapper.get("config")
        if not isinstance(config, dict):
            return None
        if any(not isinstance(key, str) for key in config):
            return None
        if any(not isinstance(item, str) for item in config.values()):
            return None
        mapper["config"] = dict(config)
        rank = _observed_mapper_rank(mapper)
        if rank is None or rank in seen_ranks:
            return None
        seen_ranks.add(rank)
        ranked_mappers.append((rank, mapper))

    ranked_mappers.sort(key=lambda item: item[0])
    ordered = [mapper for _, mapper in ranked_mappers]
    candidate_data = registration.model_dump(by_alias=True)
    candidate_data["protocolMappers"] = ordered
    try:
        candidate = RelyingPartyRegistration.model_validate(candidate_data)
        validate_relying_party_registration(candidate)
    except Exception:
        return None
    return [
        mapper.model_dump(by_alias=True)
        for mapper in candidate.protocol_mappers
    ]
'''


OLD_COMPARISON = '''def _observable_client_matches(
    registration: RelyingPartyRegistration,
    client: dict,
) -> bool:
    """Compare every field in the closed secret-free client profile."""
    desired = registration.model_dump(by_alias=True)
    return all(client.get(key) == value for key, value in desired.items())
'''


NEW_COMPARISON = '''def _observable_client_matches(
    registration: RelyingPartyRegistration,
    client: dict,
) -> bool:
    """Compare closed client state after normalizing vendor mapper output."""
    desired = registration.model_dump(by_alias=True)
    observed_mappers = _normalized_observed_mappers(
        client.get("protocolMappers"),
        registration,
    )
    if observed_mappers is None:
        return False
    if observed_mappers != desired["protocolMappers"]:
        return False
    return all(
        key == "protocolMappers" or client.get(key) == value
        for key, value in desired.items()
    )
'''


def main() -> None:
    """Insert normalization helpers and replace the raw mapper comparison."""
    source = STATE_PATH.read_text(encoding="utf-8")
    marker = "\ndef _observable_client_matches(\n"
    if source.count(marker) != 1:
        raise SystemExit("unexpected observable comparison marker")
    if source.count(OLD_COMPARISON) != 1:
        raise SystemExit("unexpected observable comparison implementation")
    source = source.replace(marker, HELPERS + marker, 1)
    source = source.replace(OLD_COMPARISON, NEW_COMPARISON, 1)
    STATE_PATH.write_text(source, encoding="utf-8")


if __name__ == "__main__":
    main()
