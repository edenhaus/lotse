<!-- Title: Conventional Commit (feat:, fix:, docs:, ci:, ...). It becomes the squash commit. -->

## What and why

<!-- One paragraph: what this implements or changes, and why. -->

## Checklist

- [ ] Every changed behavior, error paths included, has a test in this PR; a bug fix starts with a failing regression test
- [ ] Spec clauses cited in the code; any deviation carries a `SPEC-DEVIATION` tag
- [ ] New parser or protocol code has a fuzz target
- [ ] API messages changed: JSON Schema regenerated and the diff is intentional
- [ ] New dependency: justified in `Cargo.toml`, `default-features = false`, `.cargo/deny.toml` wrappers extended
- [ ] Logging: state changes and decisions logged with their reason at the right level
- [ ] I can explain every line of this change (`AI_POLICY.md`)
