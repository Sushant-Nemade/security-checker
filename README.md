# 5-Minute Security Checker

Local TypeScript CLI for finding likely exposed credentials. It reports file and line, redacts secret values, and can write SARIF for GitHub code scanning.

## Run

From the workspace root, run `pnpm install`, `pnpm --filter security-checker build`, and `node apps/security-checker/dist/cli.js PATH --sarif report.sarif`.

The scanner ignores Git metadata, dependencies, build outputs, symlinks, binary files, and files over 1 MiB. Review all findings: regex matches and entropy are only screening signals. If an actual secret was committed, revoke it before cleaning history.

## GitHub Action

The included `action.yml` can be used from a workflow in this repository. Configure `security-events: write` to upload SARIF. Pin third-party actions to reviewed commits before a production rollout.

## Security boundary

The CLI reads local files. It does not upload file contents. Avoid exposing a repository upload UI on a public tunnel without authentication, file limits, and isolation.

The optional `web/index.html` scans selected text files entirely in the browser. It does not recurse into directories or generate SARIF; use the CLI for those tasks.
