## Summary

<!-- 1-3 bullets describing what this PR does and why. -->

## Changes

| File | Change |
|------|--------|
| `path/to/file` | What changed and why |

## Test Plan

- [ ] `make lint` - all checks pass (golangci-lint, yamllint, actionlint, hadolint, zizmor)
- [ ] `make test-race` - unit tests pass with the race detector
- [ ] `make compose-config` - valid compose file
- [ ] `make docker-build` - local image builds

## Checklist

- [ ] Conventional commit format used in every commit (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`)
- [ ] Branch name follows `type/description` convention
- [ ] No `Co-Authored-By` or AI attribution trailers in commit messages
- [ ] Docs updated if behavior changed (README, SECURITY, INTEGRATION, ARCHITECTURE)
- [ ] CHANGELOG entry added if this is a user-visible change

## Closes

<!-- Link the issue this PR resolves, if any. e.g. `Closes #12` -->
