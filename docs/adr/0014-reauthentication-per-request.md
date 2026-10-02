# ADR-0014: re-authentication for credential changes is per request, and a service cannot pass it

**Status:** accepted

## Context

settings-api's catalogue has `keyring.require_reauth_for_credential_changes`: when a person
turns it on, adding, replacing or removing a stored credential needs their account password
again, even inside a live session. It is the control that stops a stolen session token, or a
service holding the person's user token, from becoming every account the vault can reach. It
is owner-writable only in settings-api, and its entry *refuses* rather than falling back
during an outage.

keyring had no such check. Something had to carry the password, and something had to decide
what an outage means.

## Decision

**The password travels with the change, as `current_password`, on every route that changes a
credential.** In the body `put_api_key` and `put_password` already have; as the whole,
optional body of `authorize_connection`, `delete_connection` and `delete_profile`. It is
checked by `AccountService.confirm_password`, which is guarded like a login: a wrong password
counts toward the lockout, a locked or disabled account is refused whatever is sent, and every
path hashes.

**A password that is sent is always checked**, whatever the setting says.

**A service cannot pass it.** The delegated routes take no password; a service never sees one.
With the setting on, `authorize_delegated_connection` and `delete_delegated_connection` answer
403, and the person makes the change with their own session.

**An outage is unknown, not off.** While settings-api cannot say, the setting reads as
unknown. A change that carries the right password goes ahead — it has satisfied the setting
whichever way it is set, so nothing is guessed — and one that does not is a 503. A login never
reads the setting, so an outage cannot fail a login over it.

**The OAuth callback is not checked; the start of the flow is.** The callback is a browser
redirect carrying only single-use state. The person or service that began the flow is the one
present, so that is where the check sits.

**An administrator deleting somebody else's profile is not checked.** They do not have the
person's password; the permission and the audit entry are what hold them to account. The owner
is still notified if they asked to be. **An administrator deleting their own profile is.** It is
a change to their own credentials, and without the check a stolen owner's session would remove
them through `delete_account_profile` with no password at all. That route has no password to
offer, so with the setting on it answers 403 and names `delete_profile`.

## What we gave up

**A "sudo mode" window.** The usual alternative is a re-authenticate endpoint that marks the
session as recently proven for a few minutes. It is friendlier for somebody adding five keys in
a row, and it keeps passwords out of `DELETE` bodies. It also means a session token stolen
inside that window is worth everything again, which is the threat this setting exists for, and
it would need a new route, a migration and a session column. Per request is the faithful
reading of "entering the account password again" and costs one Argon2 hash per change.

**Request bodies on `DELETE`.** HTTP allows them and FastAPI reads them, but some clients make
them awkward. The body is optional, so nothing changes for anybody who has not turned the
setting on.

## When to revisit

If people who turn this on find themselves re-entering the password many times a minute, a
short, single-session proof window — issued by a password check and bound to the session it
was proven in — is the next step. A service must still never be able to obtain one.
