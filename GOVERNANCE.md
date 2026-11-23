# Official project governance

The official ARGUS-1 source repository is
https://github.com/Archymedes-Lab/argus-1. ARGUS-INSTINCT is the product name;
JARVIS is the engine's internal name. The current cofounder maintainers are
@chrisnkuno and @soniAineza4. Area responsibilities are listed in
[CONTRIBUTING.md](CONTRIBUTING.md). Changes to maintainers and this policy
require a reviewed pull request, with a public record after publication.

Anyone may propose issues, documentation, tests or code. Externally copyrighted
contributions require the documented commercial rights in CONTRIBUTING.md before merge.
DCO alone is insufficient for separate commercial licensing. Maintainers review
scope, correctness, privacy, security and maintenance cost. A contribution
creates no right to merge access, official branding or release signing keys.
Review decisions should explain concrete technical reasons; disagreements can
be escalated to both maintainers in the PR. Security details use the private
channel in [SECURITY.md](SECURITY.md).

The official main branch moves through pull requests and passing required
checks. Maintainers merge ordinary contributions. External contributors may
never merge merely because CI passes. Trust-anchor changes in
[CODEOWNERS](.github/CODEOWNERS), including licensing, governance, security,
workflows and release tooling, follow ASES independent review requirements.
Either cofounder may merge after required CI; the other cofounder's approval is
optional under the owner decision of 2026-11-09. CODEOWNERS is
review routing; GitHub branch/ruleset enforcement must be verified separately.
Do not bypass reviews or tests because a model recommends a change.

Only listed maintainers authorize official releases through the existing
[release process](docs/guides/RELEASING.md). Release signatures and independently
verified signer fingerprints establish provenance; a tag or repository name
alone does not. Forks may publish their own releases under their own identity
and signing keys in accordance with the license and trademark policy.
