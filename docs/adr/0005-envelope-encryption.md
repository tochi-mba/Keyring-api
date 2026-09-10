# ADR-0005: one master key, envelope encryption, no per-tenant keys

**Status:** accepted

## Context

Credentials are stored on local disk. Something has to encrypt them, and something has to
hold the key.

## Decision

Envelope encryption with a single master key from the environment
(`KEYRING_MASTER_KEY`, base64 of 32 bytes). Each secret gets a fresh AES-256-GCM data key,
which is itself encrypted by the master key and stored alongside the ciphertext. Files are
mode 0600 in directories that are mode 0700.

Explicitly **not** per-tenant data keys.

## Why

**Why envelope rather than encrypting directly with the master key.** The master key then
covers 32 bytes per secret rather than every credential in the vault, which bounds how much
material one key protects; and re-keying later is rewrapping a few data keys rather than
decrypting and re-encrypting everything.

**Why the file mode matters as much as the cipher.** They defend against different
attackers. Encryption covers a stolen disk or a mishandled backup. 0600 covers every other
process and user on the machine, which is by far the likelier reader. The directories are
0700 too, because a world-readable directory leaks which services each person has connected
even when every file inside is unreadable.

**Why not per-tenant keys.** They would buy cryptographic shredding on account deletion —
destroy the key, and the data is unrecoverable even from a backup. At a dozen known users
that is key-management complexity bought for a property that deleting the files already
provides well enough.

## What it costs

**The master key is a backup dependency and a single point of failure in both directions.**
Lose it and every stored credential is unreadable, with no recovery. Leak it alongside the
files and they are all readable. It belongs in the deployment's secret handling — never in
the repository, the image, or a `.env` that gets committed.

Deleting an account deletes its files rather than shredding a key, so recovery from an old
backup remains possible in a way it would not be with per-tenant keys.

## What would change our minds

Regulated data, or a user who can credibly demand cryptographic erasure. Neither applies to
a service run for one household.
