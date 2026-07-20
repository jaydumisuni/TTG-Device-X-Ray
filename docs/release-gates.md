# Merge and release gates

## Required merge check

Configure the `main` branch or repository ruleset to require this status check:

```text
CI / CI Gate
```

Recommended repository settings:

- require a pull request before merging
- require the branch to be up to date before merging
- require `CI / CI Gate`
- block force pushes and branch deletion
- dismiss stale approvals when the head changes
- allow repository administrators to use the same gate

The aggregate gate succeeds only after the package/quality job, every supported Linux Python test
lane, and the Windows smoke lane succeed.

## Release gate

Releases are created only from tags matching `vMAJOR.MINOR.PATCH`. The Release workflow:

1. checks out the exact tag
2. runs the complete local quality gate
3. verifies tag, project, and package versions agree
4. builds wheel and source archives
5. validates metadata with Twine
6. writes SHA-256 checksums
7. creates a GitHub provenance attestation
8. publishes the GitHub Release

A release failure leaves the tag intact but does not publish a successful release artifact set.
