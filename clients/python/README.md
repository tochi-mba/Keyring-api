# keyring-client

How every service in the LUCY family believes a keyring token and fetches a credential. It
lives in the keyring repository because keyring owns the contract it implements: the token
format, the JWKS document, and the two internal endpoints.

```python
from keyring_client import CredentialClient, ExactAudience, JwksClient, SystemClock, TokenVerifier

clock = SystemClock()
jwks = JwksClient(url="http://127.0.0.1:8001/.well-known/jwks.json", clock=clock)
verifier = TokenVerifier(jwks=jwks, issuer="http://127.0.0.1:8001", clock=clock)

identity = await verifier.verify(token, audience=ExactAudience("example-tool"))
identity.account_id  # keyring's opaque account id

credentials = CredentialClient(base_url="http://127.0.0.1:8001", service_token=service_token)
resolved = await credentials.resolve_credential(
    user_token=token, profile="personal", service="tmdb"
)
resolved.headers  # attach these; never store them
```

Pass your service's own logger (`logger=get_logger(__name__)`) so refusal reasons land in
your structured logs. Map `AuthenticationError` to 401 and `KeyringUnreachableError` to 503.

In tests, use `keyring_client.testing`: `FakeKeyring().transport()` serves a real JWKS
document and keyring's internal endpoints in their real shapes, `mint()` signs real RS256
tokens, and `forge_hs256()` / `forge_unsigned()` are the attacks a verifier must refuse.

See `docs/client.md` in the keyring repository for the full contract and the adoption guide.
