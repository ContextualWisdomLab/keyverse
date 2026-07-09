"""Atheris fuzz target for account matching invariants."""
from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from app.matching import decide_match, have_matching_verified_email
    from app.models import FederatedIdentity, MatchReason, UserAccount


def _text(provider: atheris.FuzzedDataProvider, max_length: int = 48) -> str:
    return provider.ConsumeUnicodeNoSurrogates(max_length)


def _account(provider: atheris.FuzzedDataProvider) -> UserAccount:
    """Build a bounded account model from arbitrary bytes."""
    link_count = provider.ConsumeIntInRange(0, 3)
    links = [
        FederatedIdentity(
            identity_provider=_text(provider) or "idp",
            external_user_id=_text(provider) or "subject",
            external_user_name=_text(provider) or None,
        )
        for _ in range(link_count)
    ]
    return UserAccount(
        user_id=_text(provider) or "user",
        user_name=_text(provider) or None,
        email=_text(provider) or None,
        is_email_verified=provider.ConsumeBool(),
        state="active" if provider.ConsumeBool() else "disabled",
        first_name=_text(provider) or None,
        last_name=_text(provider) or None,
        external_id=_text(provider) or None,
        federated_identities=links,
    )


def TestOneInput(data: bytes) -> None:
    """Exercise matching policy over arbitrary user/link/email combinations."""
    provider = atheris.FuzzedDataProvider(data)
    survivor = _account(provider)
    duplicate = _account(provider)
    decision = decide_match(
        survivor,
        duplicate,
        explicit_link=provider.ConsumeBool(),
    )

    if not decision.matched:
        assert decision.reason is MatchReason.NO_MATCH
    if decision.reason is MatchReason.VERIFIED_EMAIL:
        assert have_matching_verified_email(survivor, duplicate)
    if not have_matching_verified_email(survivor, duplicate):
        assert decision.reason is not MatchReason.VERIFIED_EMAIL


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
