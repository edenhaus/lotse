# Contributing

Thanks for helping build lotse. The short version:

1. **Design first.** A new feature starts as a design discussion in an
   issue, not as code.
2. **Set up with mise.** `mise install` fetches the pinned toolchain and
   tools and installs the git hooks. `mise run check` runs everything CI
   runs. The commands are listed in [AGENTS.md](AGENTS.md#commands).
3. **Follow the conventions** in [AGENTS.md](AGENTS.md): no untested
   code, everything documented, every spec clause cited, structured
   logging, strict lints.
4. **Conventional Commits.** The hook checks commit messages; pull requests
   are squash-merged with their title, which CI also checks.
5. **Fill in the pull request checklist.** Reviewers use it.
6. **Security issues** go through [SECURITY.md](SECURITY.md), not the issue
   tracker. Read [AI_POLICY.md](AI_POLICY.md) if you use AI tools.

By contributing you agree that your contribution is licensed as described
in [README.md](README.md#license).
