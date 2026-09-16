"""Everything that happens to an account: invite, login, logout, reset, delete.

This is the highest-risk module in the service, and most of what it does is arrange for
two code paths to be indistinguishable from the outside.

Three rules run through all of it:

**Nothing reveals whether an account exists.** A login against an unknown address and a
login with the wrong password raise the same error *and* cost the same CPU -- the second
half via :meth:`PasswordHasher.verify_dummy`, because identical error messages are
undone by a response that comes back ten times faster. A reset request for an unknown
address returns ``None``, which the API renders exactly like a successful one.

**Anything that changes a password ends every other session.** A password change and a
reset are both actions someone takes *because* they think they have been compromised. If
the attacker's session survived, the action would have done nothing about the thing they
actually hold. Outstanding reset tokens die with the sessions, for the same reason.

**Guessing is limited in two independent ways.** A per-account lockout stops someone
working on one person's password; a per-caller rate limit stops someone working through
a list of addresses. They are keyed differently on purpose -- see
:mod:`keyring_api.accounts.ratelimit`.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from typing import TYPE_CHECKING

from keyring_api.accounts.tokens import hash_token, new_token
from keyring_api.core.logging import get_logger
from keyring_api.domain.accounts import (
    Account,
    AccountStatus,
    check_password_policy,
    new_account_id,
    normalize_email,
)
from keyring_api.domain.errors import (
    AccountExistsError,
    AuthenticationError,
    InvalidEmailError,
    InvalidGrantError,
    RateLimitedError,
)
from keyring_api.domain.grants import Grant, GrantPurpose, new_grant_id
from keyring_api.domain.rbac import DEFAULT_ROLE, OWNER
from keyring_api.domain.sessions import Session, new_session_id
from keyring_api.notifications.templates import invite_message, reset_message

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.accounts.hashing import PasswordHasher
    from keyring_api.accounts.ratelimit import RateLimiter
    from keyring_api.accounts.store import AccountStore, GrantStore, SessionStore
    from keyring_api.core.clock import Clock
    from keyring_api.core.config import Settings
    from keyring_api.core.preferences import PreferenceSource
    from keyring_api.notifications.outbox import Outbox

logger = get_logger(__name__)

BAD_CREDENTIALS = "email or password is incorrect"
"""The one message every failed login gets, whatever actually went wrong."""

BAD_GRANT = "this link is invalid or has expired"
"""Likewise for invites and resets: unknown, expired and already-used are one answer."""

SCOPE_LOGIN = "login"
SCOPE_RESET = "reset"
SCOPE_INVITE = "invite"
SCOPE_RESET_RECIPIENT = "reset-recipient"
"""Caps how often one *address* is mailed, whoever asks.

The per-caller limit stops one attacker hammering the endpoint. This stops many callers,
or one behind changing addresses, from using password reset to flood somebody else's
inbox -- an attack that costs the attacker nothing and lands entirely on a third party.
Keyed by a hash of the address so the limiter never holds plaintext addresses.
"""


@dataclass(frozen=True, slots=True)
class IssuedGrant:
    """A freshly minted invite or reset token, returned to the issuer once.

    The plaintext token exists only in this object and in whatever the caller does with
    it. Nothing stores it.
    """

    grant_id: str
    token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class LoginResult:
    """A new session. ``token`` is the only copy that will ever exist."""

    session_id: str
    account_id: str
    token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SweepResult:
    """What one retention pass removed."""

    sessions: int
    grants: int
    rate_limit_records: int


class AccountService:
    """Orchestrates the account stores, the hasher, and the two guessing defences."""

    # PLR0913: eight collaborators, every one of them keyword-only and injected. That
    # is what constructor injection looks like when the alternative -- a bundle object
    # the service reaches into -- would hide which dependencies it actually has.
    def __init__(  # noqa: PLR0913
        self,
        *,
        accounts: AccountStore,
        sessions: SessionStore,
        grants: GrantStore,
        hasher: PasswordHasher,
        limiter: RateLimiter,
        outbox: Outbox,
        clock: Clock,
        settings: Settings,
        preferences: PreferenceSource,
    ) -> None:
        self._accounts = accounts
        self._sessions = sessions
        self._grants = grants
        self._hasher = hasher
        self._limiter = limiter
        self._outbox = outbox
        self._clock = clock
        self._settings = settings
        self._preferences = preferences

    @property
    def delivers_email(self) -> bool:
        """Whether tokens reach people by mail rather than through the operator.

        The API reads this to decide whether to return an invite token in its response.
        With delivery on, the token exists in exactly one place: the recipient's inbox.
        """
        return self._outbox.is_enabled

    # -- Invites -----------------------------------------------------------------------

    async def issue_invite(self, *, email: str) -> IssuedGrant:
        """Mint a single-use invite for an address.

        Administrative, so it can afford to be explicit about an address that already
        has an account: there is no stranger on this path to leak the answer to.

        Raises:
            InvalidEmailError: if the address cannot be stored.
            AccountExistsError: if that address already has an account.
        """
        address = normalize_email(email)

        if await self._accounts.get_by_email(address) is not None:
            msg = f"an account already exists for {address!r}"
            raise AccountExistsError(msg)

        grant = await self._mint_grant(
            purpose=GrantPurpose.INVITE,
            ttl_seconds=self._settings.invite_ttl_seconds,
            email=address,
        )
        self._outbox.enqueue(
            invite_message(
                to_address=address,
                token=grant.token,
                expires_in_days=round(self._settings.invite_ttl_seconds / 86_400),
                link_base_url=self._settings.email.link_base_url,
            )
        )
        logger.info("invite_issued", grant_id=grant.grant_id)
        return grant

    async def redeem_invite(self, *, token: str, password: str, caller: str) -> Account:
        """Turn an invite into an account.

        The address comes from the invite, never from the request. Taking it from the
        request would let anyone holding one invite claim any address they liked.

        Raises:
            RateLimitedError: too many attempts from this caller.
            InvalidGrantError: unknown, expired, already used, or not an invite.
            InvalidPasswordError: the password does not meet the policy.
        """
        await self._limiter.check(
            SCOPE_INVITE,
            caller,
            limit=self._settings.rate_limit.invite_attempts,
            window_seconds=self._settings.rate_limit.invite_window_seconds,
        )
        # Checked before the grant is consumed, so a rejected password leaves the invite
        # usable and the person can try again rather than needing a new one.
        check_password_policy(password)

        grant = await self._redeem(token, GrantPurpose.INVITE)
        if grant.email is None:
            # An invite carries the address it was issued to; one that does not cannot
            # say what account to create. Refused rather than defaulted, because the
            # only default available would be an address the caller supplied.
            raise InvalidGrantError(BAD_GRANT)

        now = self._clock.now()
        # The first account to exist becomes the owner. Somebody has to be able to
        # appoint owners, and appointing one requires already being one -- so without
        # this a fresh deployment could only ever be administered through the
        # break-glass token. Every subsequent account gets the default role, which has
        # no administrative permissions at all.
        first = await self._accounts.count() == 0
        roles = (OWNER,) if first else (DEFAULT_ROLE,)

        account = Account(
            account_id=new_account_id(),
            email=grant.email,
            password_hash=self._hasher.hash(password),
            created_at=now,
            updated_at=now,
            roles=roles,
        )
        await self._accounts.add(account)
        if first:
            logger.info("first_account_became_owner", subject_id=account.account_id)

        await self._limiter.reset(SCOPE_INVITE, caller)
        logger.info("account_created", created_account_id=account.account_id)
        return account

    # -- Login -------------------------------------------------------------------------

    async def login(self, *, email: str, password: str, caller: str) -> LoginResult:
        """Authenticate and open a session.

        Raises:
            RateLimitedError: too many attempts from this caller.
            AuthenticationError: for every other failure, undifferentiated.
            PreferencesUnavailableError: settings-api refused this service's grant.
        """
        await self._limiter.check(
            SCOPE_LOGIN,
            caller,
            limit=self._settings.rate_limit.login_attempts,
            window_seconds=self._settings.rate_limit.login_window_seconds,
        )

        account = await self._find_for_login(email)
        if account is None:
            # The dummy verification is the whole point of this branch: without it, a
            # login against an unknown address returns as fast as a dictionary lookup
            # and the response time says which addresses are real.
            self._hasher.verify_dummy(password)
            logger.info("login_failed", reason="unknown_account")
            raise AuthenticationError(BAD_CREDENTIALS)

        now = self._clock.now()
        if account.is_locked(now=now) or account.status is not AccountStatus.ACTIVE:
            # Verify anyway, and throw the answer away. This branch is the only one that
            # could return without hashing, and a login that comes back in microseconds
            # while every other outcome takes ~50ms is an oracle: it says this address
            # has an account, and that the account is locked or disabled. The identical
            # error message does not help if the clock disagrees with it.
            self._hasher.verify(account.password_hash, password)
            logger.info("login_failed", reason="not_authenticable", subject_id=account.account_id)
            raise AuthenticationError(BAD_CREDENTIALS)

        if not self._hasher.verify(account.password_hash, password):
            await self._accounts.save(
                account.with_failure(
                    now=now,
                    lockout_threshold=self._settings.lockout_threshold,
                    lockout_seconds=self._settings.lockout_seconds,
                )
            )
            logger.info("login_failed", reason="bad_password", subject_id=account.account_id)
            raise AuthenticationError(BAD_CREDENTIALS)

        account = await self._accept_login(account, password=password, now=now)
        await self._limiter.reset(SCOPE_LOGIN, caller)
        return await self._open_session(account, now=now)

    async def _find_for_login(self, email: str) -> Account | None:
        """Look up an account, treating an unusable address as simply not found.

        A validation error here would be a smaller oracle than a missing-account error,
        but it is still one: it tells a caller which address shapes this service
        considers real.
        """
        try:
            address = normalize_email(email)
        except InvalidEmailError:
            return None
        return await self._accounts.get_by_email(address)

    async def _accept_login(self, account: Account, *, password: str, now: datetime) -> Account:
        """Clear the failure state and upgrade the stored hash if the cost has risen.

        A successful login is the only moment the plaintext exists, so it is the only
        moment a rehash is possible. Without it, everyone who never changes their
        password stays on the parameters they signed up under.
        """
        account = account.with_success()
        if self._hasher.needs_rehash(account.password_hash):
            account = replace(account, password_hash=self._hasher.hash(password), updated_at=now)
            logger.info("password_hash_upgraded", subject_id=account.account_id)

        await self._accounts.save(account)
        return account

    async def _open_session(self, account: Account, *, now: datetime) -> LoginResult:
        """Mint a session token and store only its hash.

        Preferences are resolved here, after the password has succeeded, so a failed
        login never asks settings-api. The idle TTL is stamped on the row so a later
        settings change does not reshape this session mid-life.
        """
        prefs = await self._preferences.for_account(account.account_id)
        token = new_token()
        session = Session(
            session_id=new_session_id(),
            account_id=account.account_id,
            token_hash=hash_token(token),
            created_at=now,
            last_used_at=now,
            expires_at=now + timedelta(seconds=prefs.session_ttl_seconds),
            absolute_expires_at=now + timedelta(seconds=prefs.session_absolute_ttl_seconds),
            idle_ttl_seconds=prefs.session_ttl_seconds,
        )
        # Stored and trimmed as one operation. This used to be a loop here -- count,
        # drop the oldest, count again -- and two logins arriving together each saw room
        # the other was about to take, so the cap was advisory. An unbounded session list
        # is memory an authenticated caller allocates for free, one login at a time.
        await self._sessions.add_within_cap(session, cap=prefs.max_sessions)

        logger.info("login_succeeded", subject_id=account.account_id, session_id=session.session_id)
        return LoginResult(
            session_id=session.session_id,
            account_id=account.account_id,
            token=token,
            expires_at=session.expires_at,
        )

    # -- Sessions ----------------------------------------------------------------------

    async def resolve_session(self, token: str) -> Session:
        """Turn a presented token into a live session, extending its idle window.

        Raises:
            AuthenticationError: unknown, expired, or belonging to an account that is
                gone or disabled.
        """
        session = await self._sessions.get_by_token_hash(hash_token(token))
        if session is None:
            raise AuthenticationError(BAD_CREDENTIALS)

        account = await self._accounts.get(session.account_id)
        if account is None or account.status is not AccountStatus.ACTIVE:
            # Disabling an account has to end the sessions it already has, not merely
            # stop new logins -- otherwise the person just disabled stays signed in.
            raise AuthenticationError(BAD_CREDENTIALS)

        refreshed = session.touched(
            now=self._clock.now(),
            idle_ttl_seconds=(
                session.idle_ttl_seconds
                if session.idle_ttl_seconds is not None
                else self._settings.session_ttl_seconds
            ),
            absolute_expires_at=None,
        )
        await self._sessions.save(refreshed)
        return refreshed

    async def logout(self, session_id: str) -> bool:
        """End one session. Returns whether there was one."""
        return await self._sessions.revoke(session_id)

    async def logout_everywhere(self, account_id: str) -> int:
        """End every session for an account. Returns how many went."""
        revoked = await self._sessions.revoke_all(account_id)
        logger.info("sessions_revoked", subject_id=account_id, count=revoked)
        return revoked

    async def set_status(self, account_id: str, status: AccountStatus) -> None:
        """Enable or disable an account."""
        account = await self._accounts.get(account_id)
        if account is None:
            return

        await self._accounts.save(replace(account, status=status, updated_at=self._clock.now()))

    # -- Passwords ---------------------------------------------------------------------

    async def change_password(
        self,
        account_id: str,
        *,
        current_password: str,
        new_password: str,
        keep_session_id: str | None = None,
    ) -> None:
        """Replace a password, having proved the current one is known.

        Requiring the current password is what keeps a stolen session from being an
        account takeover: the session can be revoked, a changed password cannot be
        un-changed by its owner.

        Raises:
            AuthenticationError: the current password is wrong, or the account is gone.
            InvalidPasswordError: the new password does not meet the policy.
        """
        account = await self._accounts.get(account_id)
        if account is None or not self._hasher.verify(account.password_hash, current_password):
            raise AuthenticationError(BAD_CREDENTIALS)

        await self._set_password(account, new_password, keep_session_id=keep_session_id)

    async def request_password_reset(self, *, email: str, caller: str) -> IssuedGrant | None:
        """Mint a reset token, if that address has an account.

        Returns ``None`` rather than raising when it does not. The API renders both
        outcomes as the same "if that address exists, we have sent a link", which is the
        only shape of this endpoint that does not confirm who has an account here.

        Raises:
            RateLimitedError: unlimited reset requests are unlimited mail sent to
                somebody else's inbox.
        """
        await self._limiter.check(
            SCOPE_RESET,
            caller,
            limit=self._settings.rate_limit.reset_attempts,
            window_seconds=self._settings.rate_limit.reset_window_seconds,
        )

        account = await self._find_for_login(email)
        if account is None:
            logger.info("password_reset_requested", outcome="no_such_account")
            return None

        if not await self._may_mail(account.email):
            # Refused silently. Raising here, or returning anything different, would tell
            # the caller that this address is real -- which is exactly what the identical
            # response elsewhere in this method exists to hide. The person keeps whatever
            # link was already sent.
            logger.info("password_reset_requested", outcome="recipient_rate_limited")
            return None

        # Any older link dies now. Two live links means the older one is still a
        # password sitting in an inbox after the newer one has been used.
        await self._grants.revoke_all_for_account(account.account_id, GrantPurpose.PASSWORD_RESET)

        grant = await self._mint_grant(
            purpose=GrantPurpose.PASSWORD_RESET,
            ttl_seconds=self._settings.reset_ttl_seconds,
            account_id=account.account_id,
        )
        # Queued, not awaited. If a real address meant waiting for an SMTP round trip and
        # an unknown one returned at once, the response *time* would say which -- rebuilding
        # the enumeration oracle the identical body was there to close.
        self._outbox.enqueue(
            reset_message(
                to_address=account.email,
                token=grant.token,
                expires_in_minutes=round(self._settings.reset_ttl_seconds / 60),
                link_base_url=self._settings.email.link_base_url,
            )
        )
        logger.info("password_reset_requested", outcome="issued", grant_id=grant.grant_id)
        return grant

    async def issue_reset_for(self, account: Account) -> IssuedGrant:
        """Mint a reset token for an account an administrator named.

        Bypasses the per-caller rate limit and the identical-response rule, both of which
        exist to stop a *stranger* probing addresses. The caller here is already
        authenticated and already holds a permission that says they may do this; the
        audit log is what holds them to it.

        The per-recipient mail cap still applies, so this cannot be used to flood
        somebody's inbox either.
        """
        if not await self._may_mail(account.email):
            msg = "that address has been sent too many messages recently"
            raise RateLimitedError(msg, retry_after_seconds=self._settings.email.window_seconds)

        await self._grants.revoke_all_for_account(account.account_id, GrantPurpose.PASSWORD_RESET)
        grant = await self._mint_grant(
            purpose=GrantPurpose.PASSWORD_RESET,
            ttl_seconds=self._settings.reset_ttl_seconds,
            account_id=account.account_id,
        )
        self._outbox.enqueue(
            reset_message(
                to_address=account.email,
                token=grant.token,
                expires_in_minutes=round(self._settings.reset_ttl_seconds / 60),
                link_base_url=self._settings.email.link_base_url,
            )
        )
        logger.info("password_reset_issued_by_admin", subject_id=account.account_id)
        return grant

    async def redeem_password_reset(self, *, token: str, new_password: str, caller: str) -> Account:
        """Set a new password from a reset token, and end every session.

        Raises:
            RateLimitedError: too many attempts from this caller.
            InvalidGrantError: unknown, expired, already used, or not a reset.
            InvalidPasswordError: the new password does not meet the policy.
        """
        await self._limiter.check(
            SCOPE_RESET,
            caller,
            limit=self._settings.rate_limit.reset_attempts,
            window_seconds=self._settings.rate_limit.reset_window_seconds,
        )
        # Before consuming the token, so a rejected password does not burn the link.
        check_password_policy(new_password)

        grant = await self._redeem(token, GrantPurpose.PASSWORD_RESET)

        account = None if grant.account_id is None else await self._accounts.get(grant.account_id)
        if account is None:
            # Two ways to get here, and the same answer to both. A stored reset grant
            # that names no account cannot say whose password to set. And redeeming is
            # not the same operation as loading the account, so an account deleted in
            # between leaves a consumed token with nothing to apply it to.
            raise InvalidGrantError(BAD_GRANT)

        await self._set_password(account, new_password, keep_session_id=None)
        logger.info("password_reset_completed", subject_id=account.account_id)
        return account

    async def _set_password(
        self, account: Account, new_password: str, *, keep_session_id: str | None
    ) -> None:
        """Store a new password and invalidate everything the old one authorised."""
        check_password_policy(new_password)

        now = self._clock.now()
        await self._accounts.save(
            replace(
                account,
                password_hash=self._hasher.hash(new_password),
                failed_attempts=0,
                locked_until=None,
                updated_at=now,
            )
        )

        # Both of these are the point of the exercise, not tidying up afterwards. A
        # password change is what someone does when they believe they are compromised;
        # a surviving session or an outstanding reset link would leave the attacker
        # exactly what they had.
        await self._sessions.revoke_all(account.account_id, except_session_id=keep_session_id)
        await self._grants.revoke_all_for_account(account.account_id, GrantPurpose.PASSWORD_RESET)

    # -- Deletion ----------------------------------------------------------------------

    async def delete_account(self, account_id: str) -> bool:
        """Remove an account and everything it owns.

        Returns whether there was an account. Sessions, grants, profiles, connections,
        roles and credential material all go with it, in the same operation -- see
        :meth:`~keyring_api.accounts.store.AccountStore.delete`. This used to be a
        sequence of calls here, and a sequence has a middle: a failure partway left an
        account gone and its credentials behind, decryptable and unreachable.
        """
        if not await self._accounts.delete(account_id):
            return False

        logger.info("account_deleted", subject_id=account_id)
        return True

    # -- Retention ---------------------------------------------------------------------

    async def sweep_once(self) -> SweepResult:
        """Drop expired sessions, grants, and rate-limit records.

        The rate-limit records matter as much as the rest: without a sweep the limiter
        is an unbounded map keyed by whatever an unauthenticated caller supplies.
        """
        widest_window = max(
            self._settings.rate_limit.login_window_seconds,
            self._settings.rate_limit.reset_window_seconds,
            self._settings.rate_limit.invite_window_seconds,
        )
        return SweepResult(
            sessions=await self._sessions.purge_expired(),
            grants=await self._grants.purge_expired(now=self._clock.now()),
            rate_limit_records=await self._limiter.purge_expired(window_seconds=widest_window),
        )

    # -- Shared ------------------------------------------------------------------------

    async def _may_mail(self, address: str) -> bool:
        """Whether this address may be mailed again inside the window."""
        try:
            await self._limiter.check(
                SCOPE_RESET_RECIPIENT,
                hash_token(address),
                limit=self._settings.email.max_messages_per_address_per_window,
                window_seconds=self._settings.email.window_seconds,
            )
        except RateLimitedError:
            return False
        return True

    async def _mint_grant(
        self,
        *,
        purpose: GrantPurpose,
        ttl_seconds: float,
        email: str | None = None,
        account_id: str | None = None,
    ) -> IssuedGrant:
        """Create a grant, storing only the hash of its token."""
        now = self._clock.now()
        token = new_token()
        grant = Grant(
            grant_id=new_grant_id(),
            purpose=purpose,
            token_hash=hash_token(token),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            email=email,
            account_id=account_id,
        )
        await self._grants.add(grant)
        return IssuedGrant(grant_id=grant.grant_id, token=token, expires_at=grant.expires_at)

    async def _redeem(self, token: str, purpose: GrantPurpose) -> Grant:
        """Consume a token, or raise the one indistinguishable error.

        The purpose is checked *after* redemption rather than before, so a token minted
        for the other flow is still burned by being presented at the wrong endpoint --
        an attacker probing with a stolen token does not get to keep it.
        """
        grant = await self._grants.redeem(hash_token(token), now=self._clock.now())
        if grant is None or grant.purpose is not purpose:
            raise InvalidGrantError(BAD_GRANT)
        return grant
