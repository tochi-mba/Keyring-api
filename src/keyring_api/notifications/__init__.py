"""Delivering invite and password-reset links to the person they are for.

Kept behind a port with a disabled default, because a credential vault that cannot start
without an SMTP server is a credential vault nobody can start.
"""
