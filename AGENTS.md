# crem

A project-agnostic CLI for Apple code signing: certificates, provisioning profiles, and the CI secrets that carry them. Agents and humans both use it.

## Architecture

- Hexagonal: the domain decides what a team's signing state should be; adapters only talk to providers. Define ports from the domain's perspective.
- Expect more adapters for vaults and secret stores; keep providers behind ports.
- Packages own one responsibility each; no catch-all packages (`utils`, `common`, `core`).
- Model the domain with types that make invalid states unrepresentable.

## Safety

- Commands that change App Store Connect, a vault, or a secret store are dry runs unless `--execute` is passed.
- Never print, log, or persist secret material outside a vault adapter.
- Refuse operations that would break signing, such as revoking the last valid certificate or deleting the profile CI uses.
- Against real accounts, run read-only unless the operator approved the specific change.

## Working

- Split multi-slice requests into independently verifiable, reviewable deliverables.
- Verify with the smallest check that fails if the behavior breaks; fake external systems at the boundary.
- Before submitting, run `gofmt`, `go vet`, and `go test`, and have a subagent review correctness and security.

## Code review

- When `mg` is connected to the operator's hub, publish only with `mg submit` (never `git push` or `gh pr create`), following the installed `mergegate` skill. Run `mg init --project crem` in new clones and branch from `mergegate/main`.
- Commits and PRs carry only the operator's authorship, with no mention of AI tools.
