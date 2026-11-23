"""Sealed notifications to the owner's phone through a hosted relay.

docs/architecture/ARGUS-NOTIFY.md. The server only makes outbound HTTPS
requests; the relay stores ciphertext; the phone decrypts.
"""
