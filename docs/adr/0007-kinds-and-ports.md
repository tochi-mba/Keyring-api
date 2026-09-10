# ADR-0007: credential kinds grow; consumption ports do not

**Status:** accepted

## Context

Credential kinds multiply forever: OAuth authorization code, client credentials, device
flow, OAuth 1, API key, basic auth, JWT login, cookie login, client certificate, SSH key,
cloud provider keys. Modelling each one as a thing every consumer must understand means
every new service touches every consumer.

## Decision

Four narrow ports, expected never to change, and kinds map onto them:

| Port | Answers | Used by |
| --- | --- | --- |
| `HttpAuth` | "what do I attach to this request?" (async — may refresh) | API-backed callers |
| `FormSecrets` | "what do I type into this login form?" | browser login recipes |
| `BrowserIdentity` | "which proxy and fingerprint?" | a browser runtime |
| `TransportAuth` | "which certificate or key?" | transport-level clients |

Three kinds are implemented across two of those ports: `oauth2_authorization_code` (which
refreshes), `api_key` (which does not), and `password` (+ optional TOTP seed, consumed by a
form rather than a header). `BrowserIdentity` and `TransportAuth` are declared with no
adapter.

## Why

Adding a service later means adding a kind and mapping it onto an existing port. No
consumer changes — which is the entire claim, and three kinds across two ports is what
tests it rather than assuming it. A design that only ever served one kind would look fine
and prove nothing.

`HttpAuth` is async *because* answering may require a refresh. A synchronous port would
force every caller to check expiry and refresh itself, which is exactly the knowledge this
service exists to hold in one place.

The two unimplemented ports are declared so mutual TLS and egress proxies have an obvious
home when they are needed, rather than being bolted onto `HttpAuth`, where they do not fit,
by whoever needs them first.

## Explicitly not built

**A generic "POST me a URL and I'll forward it with your credentials" proxy.** That is a
confused deputy: anything that could reach it could use every stored credential against any
host. Consumers name the service they talk to.

## What it costs

A kind that fits none of the four ports is a much bigger change than a kind that fits one.
That is deliberate — the ports are meant to be closed — but it means the first genuinely
novel consumer will be expensive.

## What would change our minds

A real fifth question. If one arrives, it is a fifth port and an honest admission that four
was a guess; it is not a reason to widen `HttpAuth` into a bag of optional methods.
