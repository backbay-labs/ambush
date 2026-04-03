"""Calico archetype — deception agent.

Deploys and manages deception infrastructure:
- Honeypots (service emulators)
- Canary tokens (tripwire credentials/files)
- Decoy network segments

Coordinates with Whiskers to monitor honeypot interactions.
Low-risk autonomous action (deploying bait, not blocking traffic).
"""
