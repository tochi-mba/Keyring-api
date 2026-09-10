# ADR-0009: invite-only registration

**Status:** accepted

## Context

The service is on the internet. Somebody has to be able to create accounts.

## Decision

**No public registration endpoint exists.** An account comes into being only by redeeming
a single-use, expiring invite, minted by a caller holding the `accounts:invite`
permission.

## Why

Invite-only costs nothing here and removes a category of problems. Every user is somebody
the operator knows personally, so open registration was never going to be used by a
stranger for a legitimate purpose. Removing it removes signup abuse, spam accounts, and an
entire account-enumeration surface, for no loss of function.

## What it costs

Somebody has to issue every invite, and no email is sent unless mail is configured
(ADR-0011). At the scale this is built for, that is a conversation the operator was going
to have anyway.

## What would change our minds

More users than a person can onboard by hand — which is also roughly where ADR-0003's
build-versus-buy calculation flips.

## Superseded in part

This ADR originally also said "administration is the operator, not an account: there is no
`is_admin` flag". That is no longer true — see
[ADR-0010](0010-rbac.md). The environment token survives as a break-glass
recovery path rather than as the only way to administer the service.
