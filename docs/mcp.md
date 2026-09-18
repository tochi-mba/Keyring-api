# Fronting keyring with an MCP server

Nothing MCP-specific is implemented. What exists is the groundwork that makes the wrapper
a wrapper rather than a rewrite — and, more importantly, a decision about **which
operations should ever become tools**, which matters more here than in most services.

## The rule that matters

An MCP tool is something a model can decide to call. So the question for every operation is
not "can this be exposed" but "what happens the first time a model calls it for a bad
reason".

| Expose | Why |
| --- | --- |
| `list_profiles`, `get_profile` | A model benefits from knowing which identities exist and whether each is live. Neither returns a secret. |
| `get_health` | Cheap, and answers "is the thing I depend on working". |

| Never expose | Why |
| --- | --- |
| `resolve_form_secrets` | The one operation that returns credential material. It is behind two credentials for that reason; a tool result is not a place for a password. |
| `resolve_credential` | Returns a usable Authorization header. The consuming *service* should call this, never a model. |
| Everything under `/v1/admin` | A model that can delete accounts or assign roles is a model one confused turn away from an incident. |
| `login`, `change_password`, `redeem_password_reset` | Credential entry is a person's job. |
| `put_api_key`, `put_password` | Same. A model should never be the thing that types a secret. |

The general shape: **a model may ask what identities exist; the service acting for it uses
them.** That split is the whole reason `/v1/internal` requires both a service token and the
end user's token — the model never holds either.

## What is already in place

**Stable operation ids.** Every route declares one, and a contract test pins the exact set.
Most OpenAPI-to-MCP bridges generate tool names from them, so renaming one is a breaking
change for every client with a tool bound to it.

**Descriptions written for a model to read.** Every route has a real paragraph saying when
to use it and what comes back, including what it deliberately does *not* return. A contract
test requires a summary and a description of more than forty characters on every operation,
so an undescribed route cannot ship.

**Bounded payloads.** No endpoint returns unbounded lists: profiles are capped per account,
connections per profile, the audit log takes a limit. Responses stay a predictable size in a
context window.

**One error shape.** Every failure is RFC 9457 problem+json with a `request_id`, so a model
has exactly one error format to understand rather than one per endpoint.

## Wrapping it

The straightforward path is FastMCP's OpenAPI ingestion pointed at `/openapi.json`, with an
allowlist — not a denylist — of the two or three operations above. A denylist means the next
endpoint added is exposed by default, and the next endpoint added might be
`delete_account`.

A hand-written thin server is the better option if you want the tool descriptions to differ
from the HTTP ones, which they probably should: an HTTP client wants to know the status
codes, and a model wants to know when *not* to call something.

Either way the MCP server is a client of keyring like any other. It authenticates as a
service, carries the end user's short-lived token, and is bound by exactly the same rules —
including the one that says no caller can name an account it was not given a token for.

## Known gaps

**No `Idempotency-Key` handling.** Assistants retry, and a retried `create_profile` will
409 rather than returning the original result. The canonical-name conflict makes that safe
rather than duplicating, but it is not friendly. Worth adding before this is fronted by
anything that retries automatically.

**No streaming or long-poll.** Every operation here returns immediately, so there is
nothing to poll — unlike example-tool, which needed it.
