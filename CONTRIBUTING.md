# Contributing

Thanks for considering a contribution to **AI Execution Firewall** — the project is fully open source under [MIT](LICENSE) and external help is genuinely welcome.

## Quick links

- 🐛 **Bug reports / feature requests:** open an issue at <https://github.com/Shahriyar-Khan27/ai_firewall/issues>
- 📚 **Where to start:** the README's [Contributing section](README.md#contributing) lists "good first issues" — typo fixes, new SBOM registries, additional MCP host detectors, more PII patterns, statistical/ML behaviour models on top of the rule-based ones, etc.
- 🛠 **Local dev setup:** see [README.md → Install](README.md#install) (`pip install -e ".[dev]"`).

## Pull request conventions

1. **One concern per PR.** A bug fix and a refactor in the same PR is harder to review and harder to revert.
2. **Add a test.** New features land with a test in `tests/`. Bug fixes land with a regression test that fails before the patch and passes after. The test suite (currently 457 tests) must stay green on every push.
3. **Run the suite locally before pushing.**
   ```bash
   pytest -q
   ```
   CI re-runs on Python 3.11 / 3.12 / 3.13.
4. **Commit message style.** Concise subject (≤ 70 chars), then a body explaining *why* the change is needed — not what the diff already shows. Avoid commit messages that just restate the file list.
5. **No unrelated formatting churn.** If your editor reformats a file you didn't otherwise change, please revert before staging.

## Reporting security issues

If you find a vulnerability that could be exploited (e.g. a way for an AI agent to bypass the firewall, a regex DoS in a scanner, a prompt-injection that disables a check), please **don't open a public issue** — file it privately via GitHub's [Security advisories](https://github.com/Shahriyar-Khan27/ai_firewall/security/advisories/new) so we can fix and disclose responsibly.

## Areas where help is most useful

The README lists these in detail; abbreviated here:

- **More registries** for the AI-SBOM scanner (Composer / NuGet / Go modules) — extends `ai_firewall/engine/package_registry.py`
- **Postgres / MySQL execute adapters** — currently only SQLite has a real-execute path
- **Additional MCP host detectors** — Aider, Cline, Zed have evolving config layouts
- **New PII patterns** — extends `ai_firewall/engine/pii_scan.py` (regex + Luhn-style validators welcome)
- **Statistical / ML behaviour models** on top of the rule-based audit-log heuristics in `ai_firewall/engine/behavior.py`
- **Translations and docs polish** — README, CHANGELOG, in-CLI help

## Code of conduct

Be kind, assume good faith, and keep discussion focused on the work. Nobody owes anyone free labour; everyone deserves a respectful response when they show up to help.

---

Questions about contributing that aren't covered here? Open a [discussion](https://github.com/Shahriyar-Khan27/ai_firewall/discussions) or reach out via the issues tracker.
