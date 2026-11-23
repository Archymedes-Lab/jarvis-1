# ASES exception register

Waivers of requirements in [ARCHYMEDES-SECURITY-STANDARD.md](ARCHYMEDES-SECURITY-STANDARD.md),
per its §0.4. `scripts/dev/standard_check.py` reads lines of the form

    - SC-<n> <path>  owner: <login>  risk: <what is accepted>  compensating: <controls>  expires: YYYY-MM-DD

An expiry at most 90 days away; an expired line fails CI. Non-automated
requirements use the same form with their requirement id (for example `REL-9`).

## Active

(none)

## Closed

(none)
