# ADR-0003: build a small vault rather than self-host a platform

**Status:** accepted

## Context

"Store each user's credentials for third-party APIs, refresh the tokens, hand the right
one to an agent at tool-call time" is a mature product category, not a gap. Nango, Composio,
Paragon, Arcade and Merge all do it. Nango alone covers 900+ APIs with pre-configured OAuth
settings, supports every auth type, does multi-tenant credential scoping, and is
self-hostable — this design, feature for feature, plus provider configs that would take
years to write and maintain.

(Caveat: most head-to-head comparisons in this space are published by the vendors
themselves. Treat feature claims as a starting point, not neutral evaluation.)

Two further findings shaped the decision:

- **A player in this exact category was breached three months ago.** Composio disclosed in
  May 2026 that an attacker compromised employees' Gmail OAuth tokens and reached internal
  systems, exposing roughly 5,001 user connections and 5,241 API keys. A funded company
  doing only this failed to hold it.
- **Self-hosting the obvious platform is not cheap.** Nango at production scale wants five
  Node services plus Postgres (2 CPU / 8 GB / 128 GB), Redis, Elasticsearch and object
  storage. It is Elastic License, not OSI open source, and production self-hosting requires
  an Enterprise plan.

## Decision

Build the small vault. Keep `SecretStore` and the other stores behind ports so a platform
can replace them if this ever outgrows a single box.

## Why

The actual requirement is 5–20 known, non-adversarial users — family and friends, each
with their own assistant. Five Node services plus Postgres, Redis, Elasticsearch and object
storage to serve a dozen people is more infrastructure than the workload supports, and
production self-hosting needs an Enterprise plan anyway.

What the Composio breach teaches at this scale is **proportionality, not paralysis**: the
blast radius here is your family's Spotify and site accounts. Bad, bounded, and they
trusted you with it — which is a reason to do the security basics properly, not a reason to
build like a bank.

## What it costs

No 900 pre-configured providers. Every provider this service talks to is a hand-written
config entry, and every provider's quirks are found the hard way. Nobody else is
maintaining them when a provider changes its token endpoint.

## What would change our minds

Paying strangers. The moment users are not people you know personally, the threat model
changes from "someone might read my sister's Spotify token" to "this is a target", and
that is the point at which a platform's dedicated security work is worth its
infrastructure.
