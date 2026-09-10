"""Shared kernel: configuration, time, request context, logging, and the composition root.

Every layer may import from here. ``domain`` is the exception — it stays free of even
this, so the business rules can be reasoned about with nothing else loaded.
"""
