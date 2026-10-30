"""The server shell gate: who may open it, and that the authorisation check needs a fresh grant."""
from types import SimpleNamespace

from app.api import shell


def _user(role="admin", mfa=True):
    return SimpleNamespace(id=7, role=role, mfa_enabled=mfa, email="a@example.org")


def test_only_admins_with_two_step_sign_in_when_switched_on(monkeypatch):
    monkeypatch.setattr(shell, "settings", SimpleNamespace(shell_enabled=False))
    assert "off" in shell._why_not(_user())
    monkeypatch.setattr(shell, "settings", SimpleNamespace(shell_enabled=True))
    assert shell._why_not(_user()) == ""
    assert "administrators" in shell._why_not(_user(role="analyst"))
    assert "two-step" in shell._why_not(_user(mfa=False))
