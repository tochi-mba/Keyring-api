# Architecture decision records

One file per decision that future-us would otherwise re-litigate. Each says what was
decided, what it cost, and what would make us change our minds.

| ADR | Decision |
| --- | --- |
| [0001](0001-separate-service.md) | keyring is its own service, not part of media-tool |
| [0002](0002-credentials-only.md) | keyring stores credentials and nothing else |
| [0003](0003-build-not-buy.md) | Build a small vault rather than self-host a platform |
| [0004](0004-in-memory-stores.md) | In-memory stores for v1, behind ports *(superseded by 0012)* |
| [0005](0005-envelope-encryption.md) | One master key, envelope encryption, no per-tenant keys |
| [0006](0006-server-can-decrypt.md) | The server can read every credential, and must |
| [0007](0007-kinds-and-ports.md) | Credential kinds grow; consumption ports do not |
| [0008](0008-opaque-sessions-signed-service-tokens.md) | Opaque sessions for people, signed tokens between services |
| [0009](0009-invite-only.md) | Invite-only registration |
| [0010](0010-rbac.md) | Role-based access control, and the line it does not cross |
| [0011](0011-email-delivery.md) | Email delivery, behind a port, disabled by default |
| [0012](0012-sqlite.md) | SQLite, one file, behind the same ports |
| [0013](0013-single-process.md) | One process, and the three things that say so |
