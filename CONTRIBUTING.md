# Contributing

## Ground rules
- **No real data in the repository.** Use documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
  private ranges and example.com/.net/.org. Never commit captures, logs, databases, config.yaml, .env or anything
  under secrets/ or data/. CI runs gitleaks on every push and pull request.
- Findings must stay explainable: evidence, query, baseline, alternatives, next steps. Do not claim what flow
  metadata cannot show (payloads, authentication outcome, the user behind a shared NAT without a return path).
- Firewall-changing code must only touch objects netmon created and recorded, and must be switchable.

## Workflow
1. Branch from `main`; keep changes focused.
2. Run the tests (see README "Development"); add tests with synthetic fixtures for new behaviour.
3. `ruff check app` must pass (CI runs it).
4. Update CHANGELOG.md under "Unreleased" and docs where behaviour changes.
5. Open a pull request; CI must be green.

## Commit identity
Use a neutral or project identity unless you choose otherwise; do not include personal infrastructure names in
commit messages.
