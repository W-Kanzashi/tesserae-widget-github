"""Tests for github_core (GitHub App Manifest, RS256 JWT, Installation tokens,
User OAuth + refresh, PAT fallback, legacy settings, error diagnostics) and
multi-account widget integration across all 14 widgets."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import sys
import time
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(plugin_id: str) -> Any:
    path = REPO_ROOT / plugin_id / "server.py"
    name = f"_test_gh_bundle_{plugin_id}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class _FakeSecretBox:
    """Deterministic test box verifying wrap/unwrap roundtrips without leaking plaintext."""

    def wrap(self, plaintext: str) -> str:
        return "enc:test:" + base64.urlsafe_b64encode(plaintext.encode("utf-8")).decode("ascii")

    def unwrap(self, stored: str) -> str:
        if not stored.startswith("enc:test:"):
            return stored
        return base64.urlsafe_b64decode(stored[len("enc:test:") :].encode("ascii")).decode("utf-8")


class _FakeSettingsStore:
    def __init__(self, sections: dict[str, dict[str, Any]] | None = None) -> None:
        self._sections = sections or {}

    def get_section(self, name: str) -> dict[str, Any]:
        return dict(self._sections.get(name, {}))


class _FakeHTTPResp:
    def __init__(self, payload: Any, *, status: int = 200, headers: dict[str, str] | None = None):
        self._body = (
            payload.encode("utf-8")
            if isinstance(payload, str)
            else json.dumps(payload).encode("utf-8")
        )
        self.status = status
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]

    def __enter__(self) -> _FakeHTTPResp:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def _http_error(
    code: int,
    payload: dict[str, Any] | str = "",
    *,
    headers: dict[str, str] | None = None,
    url: str = "https://api.github.com/test",
) -> urllib.error.HTTPError:
    raw = (
        payload.encode("utf-8")
        if isinstance(payload, str)
        else json.dumps(payload).encode("utf-8")
    )
    return urllib.error.HTTPError(
        url=url,
        code=code,
        msg="Error",
        hdrs=headers or {},  # type: ignore[arg-type]
        fp=io.BytesIO(raw),
    )


@pytest.fixture(scope="session")
def test_rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture
def core_env(tmp_path: Path):
    core = _load_module("github_core")
    core._INSTALL_TOKEN_CACHE.clear()
    core._PENDING_STATES.clear()

    app = Flask(__name__)
    app.secret_key = "test-secret"
    data_dir = tmp_path / "github_core_data"
    data_dir.mkdir()

    plugin = SimpleNamespace(id="github_core", data_dir=data_dir, server_module=core)
    app.config["PLUGIN_REGISTRY"] = {"github_core": plugin}
    app.config["SECRET_BOX"] = _FakeSecretBox()
    app.config["SETTINGS_STORE"] = _FakeSettingsStore()

    with app.app_context():
        yield core, app, data_dir


# ----- JWT & Manifest ------------------------------------------------


def test_build_app_jwt_produces_valid_rs256_structure(core_env, test_rsa_pem):
    core, _, _ = core_env
    token = core.build_app_jwt("123456", test_rsa_pem, now=1_700_000_000)
    parts = token.split(".")
    assert len(parts) == 3

    def _dec(part: str) -> dict[str, Any]:
        pad = "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part + pad))

    hdr = _dec(parts[0])
    body = _dec(parts[1])
    assert hdr == {"alg": "RS256", "typ": "JWT"}
    assert body["iss"] == "123456"
    assert body["iat"] == 1_700_000_000 - 60
    assert body["exp"] == 1_700_000_000 + 540


def test_build_app_manifest_includes_all_readonly_permissions(core_env):
    core, _, _ = core_env
    manifest = core.build_app_manifest("My Tesserae", "http://tesserae.local:5000/")
    assert manifest["name"] == "My Tesserae"
    assert manifest["redirect_url"] == "http://tesserae.local:5000/plugins/github_core/apps/manifest/callback"
    assert manifest["callback_urls"] == ["http://tesserae.local:5000/plugins/github_core/oauth/callback"]
    assert manifest["setup_url"] == "http://tesserae.local:5000/plugins/github_core/apps/installed"
    assert manifest["request_oauth_on_install"] is True
    assert manifest["default_permissions"] == {
        "actions": "read",
        "contents": "read",
        "discussions": "read",
        "issues": "read",
        "metadata": "read",
        "pull_requests": "read",
    }


def test_manifest_conversion_and_encryption_at_rest(core_env, monkeypatch, test_rsa_pem):
    core, _, data_dir = core_env

    def fake_urlopen(req, timeout=15):
        assert "/app-manifests/tempcode123/conversions" in req.full_url
        return _FakeHTTPResp(
            {
                "id": 99001,
                "slug": "tesserae-gh",
                "name": "Tesserae GH",
                "html_url": "https://github.com/apps/tesserae-gh",
                "client_id": "Iv1.abcdef",
                "client_secret": "super-client-secret",
                "pem": test_rsa_pem,
                "owner": {"login": "octocat"},
            }
        )

    monkeypatch.setattr(core.urllib.request, "urlopen", fake_urlopen)
    created = core.convert_manifest_code("tempcode123")
    assert created["app_id"] == "99001"
    assert created["slug"] == "tesserae-gh"
    assert created["install_url"] == "https://github.com/apps/tesserae-gh/installations/new"
    assert created["has_oauth"] is True
    assert "pem" not in created
    assert "client_secret" not in created

    raw_disk = (data_dir / "accounts.json").read_text(encoding="utf-8")
    assert "super-client-secret" not in raw_disk
    assert "BEGIN PRIVATE KEY" not in raw_disk
    assert "enc:test:" in raw_disk


# ----- Installations & Multi-Org Token Minting -----------------------


def test_sync_installations_and_mint_cached_tokens(core_env, monkeypatch, test_rsa_pem):
    core, _, _ = core_env
    created_app = core._upsert_app(
        name="Tesserae GH",
        app_id="4242",
        pem=test_rsa_pem,
        client_id="Iv1.123",
        client_secret="sec",
        slug="tesserae-gh",
    )

    calls: list[str] = []

    def fake_urlopen(req, timeout=15):
        calls.append(f"{req.method} {req.full_url}")
        if "/app/installations?" in req.full_url:
            return _FakeHTTPResp(
                [
                    {
                        "id": 1001,
                        "account": {"login": "octocat", "type": "User"},
                        "repository_selection": "all",
                    },
                    {
                        "id": 2002,
                        "account": {"login": "acme-org", "type": "Organization"},
                        "repository_selection": "selected",
                    },
                ]
            )
        if "/app/installations/2002/access_tokens" in req.full_url:
            return _FakeHTTPResp(
                {"token": "ghs_org_token_1", "expires_at": "2099-01-01T00:00:00Z"}
            )
        raise AssertionError(req.full_url)

    monkeypatch.setattr(core.urllib.request, "urlopen", fake_urlopen)
    synced = core.sync_app_installations(created_app["id"])
    assert len(synced) == 2
    org_acc = next(a for a in synced if a["username"] == "acme-org")
    assert org_acc["auth_type"] == "github_app_installation"
    assert org_acc["account_type"] == "Organization"
    assert org_acc["auth_label"] == "GitHub App · Org"

    # First call mints token; second call hits in-memory cache.
    tok1 = core.get_token(org_acc["id"])
    tok2 = core.get_token(org_acc["id"])
    assert tok1 == "ghs_org_token_1"
    assert tok2 == "ghs_org_token_1"
    assert sum("access_tokens" in c for c in calls) == 1

    # Installation accounts are rejected cleanly when user-scoped endpoints require a user token.
    with pytest.raises(core.GithubCoreError) as exc:
        core.resolve_account(org_acc["id"], require_user_token=True)
    assert exc.value.code == "user_token_required"
    assert "Authorize a user" in exc.value.message


# ----- User OAuth & Auto-Refresh -------------------------------------


def test_user_oauth_exchange_and_automatic_refresh(core_env, monkeypatch, test_rsa_pem):
    core, _, _ = core_env
    created_app = core._upsert_app(
        name="Tesserae GH",
        app_id="5555",
        pem=test_rsa_pem,
        client_id="Iv1.oauth",
        client_secret="oauth-secret",
        slug="tesserae-gh",
    )

    def fake_urlopen(req, timeout=15):
        if "github.com/login/oauth/access_token" in req.full_url:
            body = req.data.decode("utf-8")
            if "grant_type=refresh_token" in body:
                return _FakeHTTPResp(
                    {
                        "access_token": "ghu_refreshed_tok",
                        "refresh_token": "ghr_rotated_refresh",
                        "expires_in": 28800,
                        "refresh_token_expires_in": 15897600,
                    }
                )
            return _FakeHTTPResp(
                {
                    "access_token": "ghu_initial_tok",
                    "refresh_token": "ghr_initial_refresh",
                    "expires_in": 10,  # already within refresh margin
                    "refresh_token_expires_in": 15897600,
                }
            )
        if req.full_url == "https://api.github.com/user":
            return _FakeHTTPResp({"login": "alice"})
        raise AssertionError(req.full_url)

    monkeypatch.setattr(core.urllib.request, "urlopen", fake_urlopen)
    acc = core.exchange_oauth_code(created_app["id"], "code123", "http://localhost/cb")
    assert acc["username"] == "alice"
    assert acc["auth_type"] == "github_app_user"

    # Because expires_in=10 < 300s refresh margin, get_token refreshes automatically!
    refreshed_token = core.get_token(acc["id"])
    assert refreshed_token == "ghu_refreshed_tok"


# ----- Legacy fallback & choices -------------------------------------


def test_legacy_settings_fallback_and_account_choices(core_env):
    core, app, _ = core_env
    assert core.account_choices(require_auth=False) == [
        {"value": "", "label": "Public (no account connected)"}
    ]
    assert core.account_choices(require_auth=True)[0]["note"] is True

    app.config["SETTINGS_STORE"] = _FakeSettingsStore(
        {"plugins": {"github_core": {"username": "legacyuser", "token_secret": "ghp_legacy_123456"}}}
    )
    assert core.get_token() == "ghp_legacy_123456"
    assert core.get_username() == "legacyuser"
    choices = core.account_choices(require_auth=True)
    assert choices == [{"value": "", "label": "Default (@legacyuser, legacy settings)"}]

    # Adding a real account supersedes legacy fallback cleanly.
    acc = core.create_account("Work PAT", "ghp_work_987654321")
    choices2 = core.account_choices(require_auth=True)
    assert choices2[0]["value"] == ""
    assert choices2[1]["value"] == acc["id"]


# ----- Error diagnostics ---------------------------------------------


def test_coerce_error_produces_clear_diagnostics(core_env):
    core, _, _ = core_env
    msg401 = core.coerce_error(_http_error(401, {"message": "Bad credentials"}), account_name="Work")
    assert "401" in msg401 and "Work" in msg401 and "/plugins/github_core/" in msg401

    reset_ts = str(int(time.time()) + 600)
    msg_rl = core.coerce_error(
        _http_error(
            403,
            {"message": "API rate limit exceeded"},
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset_ts},
        ),
        account_name="",
    )
    assert "rate limit" in msg_rl.lower() and "UTC" in msg_rl

    msg404 = core.coerce_error(
        _http_error(404, {"message": "Not Found"}), account_name="Acme Org", repo="acme/secret"
    )
    assert "acme/secret" in msg404 and "Acme Org" in msg404

    gql_msg = core.coerce_graphql_error(
        {"errors": [{"type": "FORBIDDEN", "message": "Resource not accessible by integration"}]},
        account_name="Acme Org",
        auth_type="github_app_installation",
    )
    assert gql_msg is not None and "authorize a user" in gql_msg.lower()


# ----- All 14 widgets: choices("account") & error surfacing ----------


ALL_WIDGETS = [
    "github_actions",
    "github_activity",
    "github_activity_heatmap",
    "github_ci_status",
    "github_commit_cadence",
    "github_contributions",
    "github_inbox",
    "github_pr_count",
    "github_pr_queue",
    "github_releases",
    "github_repo",
    "github_star_count",
    "github_star_growth",
    "github_streak",
]


@pytest.mark.parametrize("widget_id", ALL_WIDGETS)
def test_every_widget_exposes_account_choices_and_surfaces_missing_account(
    core_env, tmp_path, widget_id
):
    core, _, _ = core_env
    core.create_account("Personal", "ghp_personal_123456789")
    mod = _load_module(widget_id)

    rows = mod.choices("account", {})
    assert any(r["value"] == "personal" for r in rows), widget_id

    # Explicit non-existent account produces an actionable UI error (not a crash or silent empty).
    opts: dict[str, Any] = {"account": "deleted-account", "repo": "a/b", "repos": "a/b", "user": "alice"}
    out = mod.fetch(opts, {}, ctx={"data_dir": str(tmp_path / widget_id), "fresh": True})
    assert "error" in out and "deleted-account" in out["error"], (widget_id, out)


def test_pr_queue_actions_releases_surface_api_errors_instead_of_swallowing(core_env, monkeypatch, tmp_path):
    core, _, _ = core_env
    acc = core.create_account("Work", "ghp_work_123456789")
    # Set username directly in stored record for test.
    data = core._load_raw()
    data["accounts"][0]["username"] = "alice"
    core._save_raw(data)

    def boom(req, timeout=15):
        raise _http_error(403, {"message": "Resource not accessible by personal access token"})

    monkeypatch.setattr(core.urllib.request, "urlopen", boom)

    for wid, opts in [
        ("github_actions", {"account": acc["id"], "repos": "acme/api"}),
        ("github_releases", {"account": acc["id"], "repos": "acme/api"}),
        ("github_pr_queue", {"account": acc["id"]}),
    ]:
        mod = _load_module(wid)
        out = mod.fetch(opts, {}, ctx={"data_dir": str(tmp_path / wid), "fresh": True})
        assert out.get("error"), (wid, out)
        assert "403" in out["error"] and "Work" in out["error"]


def test_github_inbox_splits_search_query_on_422_for_fine_grained_pats(core_env, monkeypatch, tmp_path):
    core, _, _ = core_env
    acc = core.create_account("FineGrained", "github_pat_1234567890abcdef")
    data = core._load_raw()
    data["accounts"][0]["username"] = "alice"
    core._save_raw(data)

    seen_queries: list[str] = []

    def fake_urlopen(req, timeout=15):
        import urllib.parse

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(req.full_url).query)
        q = qs["q"][0]
        seen_queries.append(q)
        if "is:issue" not in q and "is:pr" not in q:
            raise _http_error(422, {"message": "Validation Failed"})
        if "is:issue" in q:
            return _FakeHTTPResp(
                {
                    "total_count": 1,
                    "items": [
                        {
                            "title": "Bug",
                            "number": 1,
                            "repository_url": "https://api.github.com/repos/alice/app",
                            "html_url": "https://github.com/alice/app/issues/1",
                            "created_at": "2026-10-01T00:00:00Z",
                            "updated_at": "2026-10-02T00:00:00Z",
                            "user": {"login": "bob"},
                            "comments": 0,
                            "labels": [],
                        }
                    ],
                }
            )
        return _FakeHTTPResp({"total_count": 0, "items": []})

    monkeypatch.setattr(core.urllib.request, "urlopen", fake_urlopen)
    inbox = _load_module("github_inbox")
    out = inbox.fetch(
        {"account": acc["id"], "show_discussions": False},
        {},
        ctx={"data_dir": str(tmp_path / "inbox"), "fresh": True},
    )
    assert not out.get("error")
    assert out["counts"]["issue"] == 1
    assert any("is:issue" in q for q in seen_queries)
    assert any("is:pr" in q for q in seen_queries)


def test_admin_blueprint_manifest_and_oauth_routes(core_env, monkeypatch, test_rsa_pem):
    core, app, _ = core_env
    app.register_blueprint(core.blueprint(), url_prefix="/plugins/github_core")

    def fake_urlopen(req, timeout=15):
        if "/app-manifests/mcode/conversions" in req.full_url:
            return _FakeHTTPResp(
                {
                    "id": 7777,
                    "slug": "tesserae-demo",
                    "name": "Tesserae Demo",
                    "html_url": "https://github.com/apps/tesserae-demo",
                    "client_id": "Iv1.demo",
                    "client_secret": "demo-secret",
                    "pem": test_rsa_pem,
                    "owner": {"login": "octocat"},
                }
            )
        if "github.com/login/oauth/access_token" in req.full_url:
            return _FakeHTTPResp(
                {
                    "access_token": "ghu_demo_tok",
                    "refresh_token": "ghr_demo_ref",
                    "expires_in": 28800,
                }
            )
        if req.full_url == "https://api.github.com/user":
            return _FakeHTTPResp({"login": "octocat"})
        if "/app/installations?" in req.full_url:
            return _FakeHTTPResp(
                [
                    {
                        "id": 3003,
                        "account": {"login": "demo-org", "type": "Organization"},
                        "repository_selection": "all",
                    }
                ]
            )
        raise AssertionError(req.full_url)

    monkeypatch.setattr(core.urllib.request, "urlopen", fake_urlopen)
    client = app.test_client()

    # 1) Start 1-click Manifest flow
    r_start = client.post("/plugins/github_core/apps/manifest/start", data={"name": "Tesserae Demo"})
    assert r_start.status_code == 200
    html = r_start.get_data(as_text=True)
    assert "https://github.com/settings/apps/new?state=" in html
    state = html.split("state=", 1)[1].split('"', 1)[0]

    # 2) Complete Manifest callback
    r_cb = client.get(f"/plugins/github_core/apps/manifest/callback?code=mcode&state={state}")
    assert r_cb.status_code == 302
    apps = core.list_apps()
    assert len(apps) == 1 and apps[0]["app_id"] == "7777"

    # 3) Sync org installations
    r_sync = client.post(f"/plugins/github_core/apps/{apps[0]['id']}/sync")
    assert r_sync.status_code == 302
    assert any(a["username"] == "demo-org" for a in core.list_accounts())

    # 4) Authorize user via OAuth
    r_oa = client.get(f"/plugins/github_core/apps/{apps[0]['id']}/oauth/start")
    assert r_oa.status_code == 302
    loc = r_oa.headers["Location"]
    assert "github.com/login/oauth/authorize" in loc
    oauth_state = loc.split("state=", 1)[1].split("&", 1)[0]

    r_oa_cb = client.get(f"/plugins/github_core/oauth/callback?code=ocode&state={oauth_state}")
    assert r_oa_cb.status_code == 302
    accounts = core.list_accounts()
    assert any(a["auth_type"] == "github_app_user" and a["username"] == "octocat" for a in accounts)
    assert any(a["auth_type"] == "github_app_installation" and a["username"] == "demo-org" for a in accounts)

