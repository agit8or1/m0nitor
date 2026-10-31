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
2. Run the tests (see the README, "Contributing and security"); add tests with synthetic fixtures for new behaviour.
3. `ruff check app` must pass (CI runs it, together with gitleaks and the tests).
4. **Versioning:** every change is a new version. Bump `__version__` in `app/netmon/__init__.py` (`1.12` → `1.13`),
   the image tag in `app/docker-compose.yml`, and add a `## v1.13 — YYYY-MM-DD` section at the top of
   `app/CHANGELOG.md` (the root `CHANGELOG.md` is a copy). `tests/test_version.py` checks that all three agree.
5. Update the docs where behaviour changes; screenshots come from the demo (`demo/screenshots.py`), never from a
   real network.
6. Open a pull request using the template; CI must be green.

## Local setup
- Demo with synthetic data: [docs/demo.md](docs/demo.md).
- Lint like CI: `docker run --rm -v "$PWD":/src:ro -w /src python:3.12-slim sh -c "pip install -q ruff==0.8.4 && ruff check --no-cache app"`.

## Commit identity
Use a neutral or project identity unless you choose otherwise; do not include personal infrastructure names in
commit messages.
