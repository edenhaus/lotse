# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(*Security → Report a vulnerability*). Do not open a public issue or pull
request for a security problem.

You will get an acknowledgement within three working days. We follow a
90-day coordinated disclosure window: fixes ship as patch releases that
deployments pick up by bumping the image digest, and the advisory is
published when the fix is available or the window ends, whichever is first.

## Scope

In scope: the daemon, its control API, every parser that touches camera or peer bytes,
the process sandbox, and the release pipeline. Out of scope: the client
that drives the control API (such as Home Assistant), the kernel, and
physical access.

## Supported versions

Pre-1.0, only the latest release receives fixes.
