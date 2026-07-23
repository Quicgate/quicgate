# Security policy

## Supported versions

quicgate is a rolling release. Security fixes land on `master` and are published
as a fresh `ghcr.io/maferick/quicgate:latest` image. Always run the latest image;
older image digests do not receive backported fixes.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's built-in flow:

1. Go to the [**Security** tab](https://github.com/maferick/quicgate/security) of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, the impact, and steps to reproduce.

This opens a private advisory visible only to you and the maintainer. You'll get
a response as soon as possible — this is a small hobby project, so please allow a
few days.

If you cannot use the private reporting flow, open a normal issue that only says
"security issue, please enable a private channel" (no details) and wait to be
contacted.

## Scope and hardening notes

Some things are deployment responsibilities rather than bugs — please keep them in
mind before reporting:

- **The admin UI/API (port 81) must never be exposed to the internet.** Put it
  behind quicgate itself with an access list, a VPN, or a firewall rule. Treat a
  publicly reachable admin port as a misconfiguration, not a vulnerability.
- **Change the default `admin@example.com` / `changeme` credentials** on first
  run (the app forces this) and enable 2FA.
- quicgate ships hardened TLS defaults (AEAD-only cipher suites, configurable
  minimum version, HSTS) but the operator chooses what to expose.

Reports about the default credentials existing, or about the admin port being
reachable in an intentionally-open test setup, are out of scope.
