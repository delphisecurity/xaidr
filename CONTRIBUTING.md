# Contributing to xaidr

Thanks for your interest in contributing! Please read this before opening a pull
request.

## License of contributions

This project is licensed under the [Apache License, Version 2.0](LICENSE).
By submitting a contribution, you agree that your contribution is provided under
the same Apache 2.0 license.

## Developer Certificate of Origin (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](./DCO), Version 1.1. The sign-off certifies
that you wrote the change (or otherwise have the right to submit it under the
project's open source license) as set out in the DCO.

Sign off your commits with:

```
git commit -s
```

The `-s` flag appends a trailer to the commit message in the form:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email in the trailer must be real and must match the commit
author's name and email. Anonymous or pseudonymous sign-offs are not accepted.

If you forgot to sign off, amend the most recent commit with:

```
git commit --amend -s
```

For a branch with several commits, rebase and sign each one:

```
git rebase --signoff <base-branch>
```

## Pull requests

A CI check verifies that every commit in a pull request carries a valid
`Signed-off-by` trailer. Pull requests with any unsigned commit will fail that
check and cannot be merged until every commit is signed off.
