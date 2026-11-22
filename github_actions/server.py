"""github_actions, recent CI runs across watched repos."""

from __future__ import annotations

import contextlib
import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import current_app

CACHE_TTL_S = 120
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
HISTORY_PER_WORKFLOW = 8


def _core() -> Any:
    plugin = current_app.config["PLUGIN_REGISTRY"].get("github_core")
    return plugin.server_module if plugin is not None else None


def choices(name: str, options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    del options
    if name != "account":
        return []
    core = _core()
    if core is None:
        return [{"value": "", "label": "Install GitHub Core to configure accounts.", "note": True}]
    return list(core.account_choices(require_auth=False))


def _duration_s(start: str | None, end: str | None) -> int | None:
    if not start or not end:
        return None
    try:
        s = datetime.fromisoformat(start.replace("Z", "+00:00"))
        e = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((e - s).total_seconds()))


def fetch(
    options: dict[str, Any], settings: dict[str, Any], *, ctx: dict[str, Any]
) -> dict[str, Any]:
    del settings
    raw = options.get("repos") or ""
    repos = [r.strip() for r in raw.replace(",", "\n").splitlines() if REPO_RE.match(r.strip())]
    if not repos:
        return {"error": "Add one or more repos (owner/repo, one per line).", "runs": []}

    core = _core()
    if core is None:
        return {"error": "Install and enable GitHub Core to use this widget.", "runs": []}

    account_id = (options.get("account") or "").strip() or None
    try:
        account = core.resolve_account(account_id, require_auth=False)
    except Exception as err:
        return {"error": core.coerce_error(err), "runs": []}
    account_name = str((account or {}).get("name") or "")
    acct_key = str((account or {}).get("id") or "public")

    max_per = max(1, int(options.get("max_results") or 3))
    data_dir = Path(ctx["data_dir"])
    data_dir.mkdir(parents=True, exist_ok=True)
    key = re.sub(r"[^A-Za-z0-9]", "_", f"{acct_key}_{','.join(repos)}_{max_per}")[:120]
    cache = data_dir / f"runs_{key}.json"
    if not ctx.get("fresh") and cache.exists() and time.time() - cache.stat().st_mtime < CACHE_TTL_S:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    runs: list[dict[str, Any]] = []
    errors: list[str] = []
    for repo in repos:
        try:
            payload = core.request_json(
                f"https://api.github.com/repos/{repo}/actions/runs?per_page=30",
                account_id=account_id,
            )
        except Exception as err:
            errors.append(core.coerce_error(err, account_name=account_name, repo=repo))
            continue
        all_runs = payload.get("workflow_runs") or []
        by_workflow: dict[str, list[dict[str, Any]]] = {}
        for r in all_runs:
            name = r.get("name") or ""
            by_workflow.setdefault(name, []).append(r)

        selected: list[dict[str, Any]] = []
        for name, ws in by_workflow.items():
            latest = ws[0]
            history: list[dict[str, Any]] = []
            for h in ws[:HISTORY_PER_WORKFLOW]:
                history.append(
                    {
                        "conclusion": h.get("conclusion") or "",
                        "status": h.get("status") or "",
                        "duration_s": _duration_s(h.get("run_started_at"), h.get("updated_at")),
                        "run_number": h.get("run_number"),
                    }
                )
            history.reverse()
            selected.append(
                {
                    "repo": repo,
                    "name": name,
                    "branch": latest.get("head_branch") or "",
                    "event": latest.get("event") or "",
                    "status": latest.get("status") or "",
                    "conclusion": latest.get("conclusion") or "",
                    "run_number": latest.get("run_number"),
                    "updated_at": latest.get("updated_at"),
                    "duration_s": _duration_s(
                        latest.get("run_started_at"), latest.get("updated_at")
                    ),
                    "history": history,
                }
            )
        selected.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
        runs.extend(selected[:max_per])

    if not runs and errors:
        return {"error": errors[0], "runs": []}

    runs.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
    result: dict[str, Any] = {"runs": runs}
    if errors:
        result["errors"] = errors
    with contextlib.suppress(OSError):
        cache.write_text(json.dumps(result), encoding="utf-8")
    return result
