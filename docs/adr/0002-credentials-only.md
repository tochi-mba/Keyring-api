# ADR-0002: keyring stores credentials and nothing else

**Status:** accepted

## Context

Once a service holds "the stuff you need to log in", there is pressure to put adjacent
things in it: browser profile directories, cookies, per-service settings, cache. They all
feel like the same category.

## Decision

| Lives in keyring | Lives in the consuming service |
| --- | --- |
| Passwords, TOTP seeds | Chrome profile directories (`user_data_dir`) |
| OAuth access and refresh tokens | Cookies, cache, localStorage, IndexedDB |
| API keys | Per-service settings and preferences |
| Which profiles and connections exist | Downloaded artifacts, job state |

## Why

**Size and shape.** A Chrome profile is gigabytes of cache. A vault holding kilobytes of
secrets should not also be a blob store.

**Locality.** The process launching Chromium needs that directory on its own local disk.
Shipping it from keyring over HTTP is not a real option.

**It preserves the blast-radius argument that justified splitting keyring out at all**
(ADR-0001). A vault that also stores gigabytes of browser state is not a small process.

The loop this produces: keyring supplies what is needed to *establish* a session; the
consuming service keeps the session it established. A site login is fetched from keyring
once, driven in media-tool's own browser profile, and the resulting cookies persist
locally — so later runs need no credential at all until the session expires.

## What it costs

Honesty about a real weakness: **a live session cookie is functionally equivalent to the
password that created it.** The split is by lifecycle and locality, not by sensitivity. So
each consuming service's profile directories are still credential-grade material and need
the same posture — mode 0600, outside any directory an endpoint serves from, never served
over an API, never in a casually-handled backup. That obligation moves to the consuming
service rather than disappearing.

## What would change our minds

If a consuming service ever needed to run the same browser identity from two machines,
the profile directory would have to become shared state somewhere. It still would not
belong in keyring; it would belong in that service's own object storage.
