# ADR-0011: email delivery, behind a port, disabled by default

**Status:** accepted

## Context

Invites and password resets are tokens that have to reach a person. Originally the operator
delivered them by hand over whatever channel they already used with that person. That works
for the first few people and stops working immediately after.

## Decision

An `EmailSender` port with three adapters — disabled, file, and SMTP — defaulting to
disabled.

SMTP, and only SMTP. Every provider a deployment this size would pick speaks it: Gmail with
an app password (500/day, free), Brevo (300/day, free), Resend and MailerSend (3,000/month,
free), or Amazon SES. One adapter covers all of them and no vendor SDK enters the process
that holds the credentials.

## Why the defaults are what they are

**Disabled by default**, because a credential vault that cannot start without an SMTP
server is a credential vault nobody can start. With delivery off, the token is returned to
the caller and the operator delivers it — the original flow, intact.

**The file adapter exists so that "let me see what the mail said" never becomes "log the
message".** A logged reset link is a live credential in the log pipeline, and from there in
wherever logs are shipped.

**Plain text only.** An HTML mail from a credential service is a phishing lesson pointed the
wrong way: it trains the recipient to click styled buttons in mail about their passwords.

## The security-relevant decisions

**Delivery happens off the request path.** Not for latency — `request_password_reset` must
answer identically whether or not the address has an account, and if a real address meant
waiting for an SMTP round trip while an unknown one returned at once, the response *time*
would say which. The identical body would be undone by the clock.

**With mail on, the invite token is not returned in the HTTP response.** It then exists in
exactly one place — the recipient's inbox — rather than in an inbox *and* a response body, a
proxy log, and somebody's shell history.

**SMTP credentials are refused without TLS.** Configuring a username and password with
neither STARTTLS nor implicit TLS is a startup error, not a warning. SMTP AUTH on a
plaintext connection sends the password in base64, which is not encryption — and a mailbox
that sends password resets is worth more than most of what it protects.

**There is no setting that disables certificate verification.** The absence is the feature.
It is the one knob that turns a working configuration into a silently intercepted one, and
it exists in most mail libraries because somebody once had a self-signed certificate.

**One address can only be mailed so often, whoever asks.** The per-caller rate limit stops
one attacker hammering the endpoint; this stops many callers, or one behind changing
addresses, using password reset to flood somebody else's inbox — an attack that costs the
attacker nothing and lands entirely on a third party. The counter is keyed by a hash of the
address, so the limiter never holds a list of everyone who has an account here.

**A delivery failure is swallowed.** A broken SMTP configuration must not turn password
reset into a 500, and must certainly not make a request for a real address behave
differently from one for an unknown address.

## What it costs

A queue that can drop messages when full (bounded on purpose — an unbounded set of pending
sends is memory an unauthenticated caller allocates), and a shutdown that waits up to ten
seconds to drain rather than dropping a queued reset link silently.

Mail deliverability is now a thing the operator owns: SPF, DKIM, and a from-address that
does not land in spam. That is real work and none of it is in this repository.

## What would change our minds

Nothing about the port. If a provider ever justified its API over SMTP — better bounce
handling, say — it is a fourth adapter behind the same interface.
