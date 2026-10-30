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


def test_grant_belongs_to_one_browser_session():
    a = SimpleNamespace(cookies={shell.COOKIE_NAME: "token-one"})
    b = SimpleNamespace(cookies={shell.COOKIE_NAME: "token-two"})
    user = _user()
    assert shell._grant(a, user) != shell._grant(b, user)  # another session must open it again
    assert shell._grant(a, user) == shell._grant(a, user)
    assert "token-one" not in shell._grant(a, user)  # only a hash of the token is kept
