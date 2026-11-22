# Tesserae GitHub widgets

CI status, PR queue, contributions, release feed, and activity widgets for [Tesserae](https://github.com/dmellok/tesserae), the e-ink dashboard companion.

Bundle of 15 widgets:

- **GitHub Core** (`github_core`), shared multi-account GitHub App & account manager (`/plugins/github_core/`). Supports 1-click GitHub App setup (Manifest flow), personal and multi-organization installations with automatic short-lived token minting, GitHub App User OAuth with automatic token refresh, and optional Personal Access Token fallback. No cell of its own; every other widget lets you pick which account to use.
- **GitHub Inbox** (`github_inbox`), every open issue, pull request and discussion across the repos you own, grouped by repo or by kind, with repos to leave out picked from a list or excluded by pattern.
- **GitHub Actions** (`github_actions`), CI run status for a repo's recent workflows.
- **GitHub Activity** (`github_activity`), commit / PR / issue activity feed.
- **GitHub Activity Heatmap** (`github_activity_heatmap`), a year of contribution squares.
- **GitHub CI Status** (`github_ci_status`), hero pass / fail for one workflow.
- **GitHub Commit Cadence** (`github_commit_cadence`), commits per week as a bar run.
- **GitHub Contributions** (`github_contributions`), contributor's contribution graph.
- **GitHub PR Count** (`github_pr_count`), hero count of open PRs.
- **GitHub PR Queue** (`github_pr_queue`), your open PRs and PRs awaiting your review.
- **GitHub Releases** (`github_releases`), latest releases for tracked repos.
- **GitHub Repo** (`github_repo`), repo summary card (stars, forks, recent activity).
- **GitHub Star Count** (`github_star_count`), hero total stars.
- **GitHub Star Growth** (`github_star_growth`), stars gained over time.
- **GitHub Streak** (`github_streak`), current contribution streak.

### GitHub Accounts (GitHub App)

Open **Admin pages → GitHub Core** (`/plugins/github_core/`) after installing:

1. Click **Create GitHub App (1-click)** to register a private GitHub App with read-only permissions (`actions`, `contents`, `discussions`, `issues`, `metadata`, `pull_requests`). All credentials (PEM private key, client secret, OAuth tokens) are encrypted at rest with Tesserae's `SecretBox`.
2. Click **Install on GitHub** to attach the app to your personal account and/or any number of organizations. GitHub redirects back to Tesserae, automatically syncing your installations and authorizing your user OAuth account.
3. Need another GitHub account or organization? Install the same app on another org and click **Sync installations**, click **Authorize user** for a second user account, or register a second GitHub App.
4. Pick the desired **Account** in any widget's options (blank uses the default account, or public access on widgets that don't require auth).

A **Fallback: Personal Access Token (PAT)** section is also available on `/plugins/github_core/`, and existing legacy single-token settings continue working automatically.

### GitHub Inbox

Lists what is open across every repo owned by the selected GitHub account (or username override). Issues and pull requests come from the REST search API and work without an account for public repos; discussions come from the GraphQL API and need a connected account in GitHub Core. Options: account, which kinds to show, grouping (repo, kind, flat), row cap up front; username override, extra owners/orgs, repo exclusions (picked from the selected account's repos or by `*` wildcard), order, density and labels under More options. Rows that do not fit the cell are dropped and counted in a "+N more" footer.

### Tests

```bash
python -m pytest github_core/tests github_inbox/tests
node github_inbox/tests/check.mjs
```

## Install

Settings → Widgets → Browse community widgets → Install. After restart, open **GitHub Core** (`/plugins/github_core/`) to connect your GitHub App.

## Why these moved out of the bundle

Developer-focused widgets that need GitHub credentials. The typical Tesserae user, especially a non-dev HA user, never enables them. Bundling 7+ widgets per install was inflating the picker. Marketplace is the right home.

## License

AGPL-3.0-or-later. See [LICENSE](./LICENSE).
