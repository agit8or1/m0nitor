## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] Tests pass locally (`docker build --build-arg DEV=1 -t netmon-app:test app && docker run --rm --network none netmon-app:test python -m pytest -q -p no:cacheprovider tests`)
- [ ] `ruff check app` passes
- [ ] Version bumped and a CHANGELOG section added (app changes only — see CONTRIBUTING.md)
- [ ] Docs updated where behaviour changed
- [ ] No real data: only documentation/private address ranges and example.com names; no secrets, logs or captures
