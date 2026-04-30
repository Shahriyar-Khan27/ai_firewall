# Changelog

All notable changes to the **AI Execution Firewall** VS Code extension.

## [0.2.1] — 2026-04-30

### Changed
- Refreshed README to lead with Marketplace install (rather than build-from-source), add badges, and document all six commands and the full demo flow (shell + SQL + HTTP). The 0.2.0 listing shipped with the older "build from source" README; this version updates the public Marketplace page.

## [0.2.0] — 2026-04-30

### Added
- Icon (`icon.png`) and Marketplace gallery metadata (`galleryBanner`, `keywords`, additional `categories`).
- Better `description` mentioning all four action types (shell / files / SQL / HTTP).
- `homepage`, `bugs`, and `repository` URLs pointing at the GitHub project.

### Changed
- Bumped `version` to **0.2.0** for the first Marketplace-targeted release.
- Publisher set to `sk-dev-ai`.

## [0.1.0] — 2026-04-30

### Added
- Six commands surfaced under `AI Firewall` in the Command Palette:
  - `Run Shell Command…` / `Evaluate Selected Text as Shell Command`
  - `Evaluate SQL Query…` / `Evaluate Selected Text as SQL`
  - `Evaluate HTTP Request…`
  - `Show Effective Policy`
- Themed approval webview rendering risk badge, intent/decision pills, findings, git context, and unified diff. Approve / Reject buttons.
- Status bar item (`🛡️ Firewall`) and dedicated "AI Firewall" output channel that streams CLI evaluation + execution traces.
- Three settings: `aiFirewall.guardPath`, `aiFirewall.rulesPath`, `aiFirewall.auditPath`.
- Fixed doubled `AI Firewall: AI Firewall:` prefix in command titles (now single-prefixed via the `category` field).

### Notes
- The extension is a thin wrapper around the [`ai-execution-firewall`](https://pypi.org/project/ai-execution-firewall/) Python CLI (`guard`). Install separately: `pip install ai-execution-firewall`.
