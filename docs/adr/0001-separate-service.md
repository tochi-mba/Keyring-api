# ADR-0001: keyring is its own service

**Status:** accepted

## Context

example-tool, the first consumer, needed credentials for the sites it drives. The cheapest
thing would have been a credentials module inside example-tool: no second deployment, no
HTTP hop, no second version number.

## Decision

keyring is a separate service with its own repository, deployment and lifecycle.
example-tool becomes one of its clients.

## Why

**Otherwise example-tool becomes a dependency of every other API.** A future Spotify
integration needing credentials should not mean it depends on a browser-driving tool. The
dependency arrow would point the wrong way for every service after the first.

**example-tool is already one product.** Accounts and a credential vault make it two
products sharing a repository and a version number, and the two have genuinely different
release pressures — one is iterated on, the other should change as little as possible.

**Blast radius.** A vault holding your family's OAuth tokens should be the smallest, most
auditable process you run. Inside example-tool it would share memory with Playwright driving
arbitrary third-party sites through recipes. That is a bad neighbourhood for a vault.

## What it costs

A second deployment, a second TLS certificate, a second thing to back up, and a network
hop on the path of any request that needs a credential. The hop is mitigated by service
tokens being verified locally against a JWKS (ADR-0008), so it is one call per job rather
than one per request.

## What would change our minds

Nothing short of the two services merging in purpose. If example-tool were the only client
that would ever exist, the argument would be weaker — but the second client is already
foreseen, which is what settles it.
