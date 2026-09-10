"""Pure business types and rules.

Imports nothing else in this package — not even ``core``. Enforced by an import-linter
contract, because a domain that quietly grows a dependency on the web framework stops
being testable in isolation long before anyone notices.
"""
