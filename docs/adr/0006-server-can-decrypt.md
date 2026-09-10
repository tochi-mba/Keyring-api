# ADR-0006: the server can read every credential, and must

**Status:** accepted

## Context

The obvious question about any credential vault: can the operator read what is in it?

## Decision

Yes. The server holds the master key and can decrypt every stored credential without any
user present.

## Why

It is forced, not chosen. **Unattended token refresh requires it.** A refresh token has to
be decrypted, exchanged, and re-encrypted at three in the morning with nobody logged in.
There is no arrangement in which the server refreshes your sister's Spotify token overnight
*and* cannot read her credentials.

The alternative is per-user passphrases the server never stores, which makes the vault
genuinely opaque to the operator — and breaks unattended refresh entirely, along with every
scheduled job that depends on it. That is a different product.

## What it costs

Everything the honesty section of the README says:

- **You can technically read what anyone stores.** With family and friends that is a
  conversation to have during onboarding, not a compliance control.
- **A breach exposes other people's third-party accounts, not just yours.** The Composio
  incident (ADR-0003) is what that looks like in practice.
- **A stored password is not revocable by you** — only by that person changing it at the
  service. Prefer OAuth wherever a provider offers it: a grant is scoped and revocable.
- **TOTP seeds are opt-in and separately flagged**, because storing one beside the password
  collapses that person's second factor into the same place as their first. Offer the
  choice; never default it on.
- **Many services' terms forbid a third party storing user credentials**, and automating
  logins breaches many sites' terms outright. Hosting for others makes that your exposure.

## What would change our minds

Dropping unattended refresh. If every credential use were interactive, a per-user
passphrase that the server never sees becomes possible, and the whole calculation changes.
