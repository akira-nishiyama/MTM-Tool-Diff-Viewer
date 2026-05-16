# Agent Development Rules

## Branching

- Work on the `develop` branch.
- Do not make development changes directly on `main`.

## Integration Flow

1. Make changes on `develop`.
2. Commit the changes.
3. Push `develop` to the remote repository.
4. Open a pull request from `develop` into `main`.
5. Merge into `main` through the pull request.

## Notes for Codex

- Before starting development, confirm the current branch is `develop`.
- If the current branch is not `develop`, ask before switching branches.
- Keep user-facing documentation in `README.md`.
- Keep design and implementation rationale in `doc/design.md`.
