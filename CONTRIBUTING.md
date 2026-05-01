# Contributing

Thanks for considering a contribution to AI Execution Firewall. The project is fully open source under the [MIT](LICENSE) license, and external help is welcome.

## Quick links

- **Bug reports and feature requests**: <https://github.com/Shahriyar-Khan27/ai_firewall/issues>
- **Where to start**: the README's [Contributing section](README.md#contributing) lists good first issues (typo fixes, new SBOM registries, additional MCP host detectors, more PII patterns, statistical or ML behaviour models on top of the rule-based ones, and so on).
- **Local dev setup**: see [README.md, Install section](README.md#install). `pip install -e ".[dev]"` from the repo root.

## Pull request conventions

1. **One concern per PR.** A bug fix and a refactor in the same PR is harder to review and harder to revert.
2. **Add a test.** New features land with a test in `tests/`. Bug fixes land with a regression test that fails before the patch and passes after. The test suite (currently 457 tests) must stay green on every push.
3. **Run the suite locally before pushing.**
   ```bash
   pytest -q
   ```
   CI re-runs on Python 3.10, 3.11, 3.12, 3.13, and 3.14.
4. **Commit message style.** Concise subject (70 characters or less), then a body explaining *why* the change is needed, not what the diff already shows. Avoid commit messages that just restate the file list.
5. **No unrelated formatting churn.** If your editor reformats a file you did not otherwise change, please revert before staging.

## Reporting security issues

If you find a vulnerability that could be exploited (a way for an AI agent to bypass the firewall, a regex DoS in a scanner, a prompt-injection that disables a check, or similar), please do not open a public issue. File it privately via [GitHub Security advisories](https://github.com/Shahriyar-Khan27/ai_firewall/security/advisories/new) to allow responsible coordination of a fix and disclosure.

## Areas where help is most useful

The README lists these in detail; the abbreviated version is:

- **More registries** for the AI-SBOM scanner (Composer, NuGet, Go modules). Extends `ai_firewall/engine/package_registry.py`.
- **Postgres and MySQL execute adapters.** Currently only SQLite has a real-execute path.
- **Additional MCP host detectors.** Aider, Cline, and Zed have evolving config layouts.
- **New PII patterns.** Extends `ai_firewall/engine/pii_scan.py`. Regex plus Luhn-style validators welcome.
- **Statistical or ML behaviour models** on top of the rule-based audit-log heuristics in `ai_firewall/engine/behavior.py`.
- **Translations and docs polish.** README, CHANGELOG, in-CLI help.

## Building the VS Code extension

The extension lives under `vscode-extension/` and is a separate TypeScript project from the Python package.

```bash
git clone https://github.com/Shahriyar-Khan27/ai_firewall.git
cd ai_firewall/vscode-extension
npm install
npm run compile
```

Open the `vscode-extension/` folder in VS Code and press **F5** to launch an Extension Development Host with the local build. To produce an installable `.vsix` for sideloading or Marketplace re-publish:

```bash
npx vsce package --no-yarn
```

## Code of conduct

Be kind, assume good faith, and keep discussion focused on the work. Nobody owes anyone free labour; everyone deserves a respectful response when they show up to help.

## Release flow (maintainers)

Pushing a tag that matches `v*` automatically triggers the GitHub Actions release pipeline:

1. Runs the full test matrix on Python 3.10, 3.11, 3.12, 3.13, and 3.14.
2. Builds sdist plus wheel.
3. Publishes to PyPI via Trusted Publishing (no API token stored in CI).
4. Builds standalone PyInstaller binaries for Linux, macOS, macOS-arm64, and Windows, and attaches them to the GitHub release.

The maintainer steps are:

```bash
# 1. Bump version strings (must agree across all three files).
#    pyproject.toml, ai_firewall/__init__.py, vscode-extension/package.json
# 2. Add a CHANGELOG.md entry plus a vscode-extension/CHANGELOG.md entry.
# 3. Refresh README.md and vscode-extension/README.md if user-visible
#    behaviour changed.
# 4. Commit, then tag and push:
git tag -a v0.5.1 -m "v0.5.1: short release line"
git push origin main
git push origin v0.5.1
```

PyPI typically reflects the new version within sixty seconds; the standalone binaries land within roughly five minutes.

VS Code Marketplace publishing is currently manual:

```bash
cd vscode-extension
npx vsce package --no-yarn                        # builds ai-execution-firewall-X.Y.Z.vsix
npx vsce publish --packagePath ai-execution-firewall-X.Y.Z.vsix
```

`vsce publish` requires a Personal Access Token for the `sk-dev-ai` Marketplace publisher account. Manage tokens at the [publisher manage page](https://marketplace.visualstudio.com/manage/publishers/sk-dev-ai).

## Questions

For anything not covered here, open a [discussion](https://github.com/Shahriyar-Khan27/ai_firewall/discussions) or file an issue.
