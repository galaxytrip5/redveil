# Security policy

## Reporting a vulnerability

If you find a security issue in `redveil` itself (the framework, the server, the
GUI, the licensing or the crypto), please report it privately before public
disclosure:

- Open a GitHub Security Advisory on the repository, or
- Email the maintainer through the contact listed on the GitHub profile.

Please include: the affected component, a reproduction, and the impact. You'll
get an acknowledgement within 7 days.

## Scope

In scope: the `redveil` codebase (store, server, GUI, HTTP client, licensing,
generator, APT builders) — anything that runs on the operator's machine or
touches a victim's browser during an authorised engagement.

Out of scope: the *output* of the tool (generated lures, stagers, packs) —
that's operator-controlled content, not a vulnerability of the framework.

## Responsible disclosure

Do not test against systems you don't own or have written authorisation for.
The framework ships with no "safe mode" and no ownership gate — that discipline
is the operator's, and the operator's alone.
