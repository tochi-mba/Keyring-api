"""Durable storage: one SQLite file, one connection, one thread.

This layer knows about rows and transactions and nothing else. It has no idea what an
account or a credential is -- the adapters that do live in the layers above and are
handed a :class:`~keyring_api.storage.database.Database` to talk through.

Everything that matters about the concurrency design is in :mod:`.database`. Read that
module docstring before changing anything here; the guarantees the layers above depend
on are the ones it establishes, and most of them are not visible from the call site.
"""
