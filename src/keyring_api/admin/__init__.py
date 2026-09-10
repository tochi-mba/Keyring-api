"""Administration: acting on accounts, roles, and other people's profiles.

Its own layer, above both ``accounts`` and ``credentials``, because it orchestrates the
two. It began inside ``accounts`` and the layering contract rejected it -- correctly: an
administrative action that deletes an account has to delete that account's credentials
too, and a layer that must reach sideways is a layer in the wrong place.
"""
