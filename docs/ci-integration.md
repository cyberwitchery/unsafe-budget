# ci integration

## github actions

```yaml
name: unsafe-budget

on: [push, pull_request]

jobs:
  unsafe-budget:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - name: install unsafe-budget
        run: cargo install unsafe-budget

      - name: check unsafe budget
        run: unsafe-budget check
```

### with baseline update on main

```yaml
name: unsafe-budget

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - name: install unsafe-budget
        run: cargo install unsafe-budget

      - name: check unsafe budget
        run: unsafe-budget check

  update-baseline:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: dtolnay/rust-toolchain@stable

      - name: install unsafe-budget
        run: cargo install unsafe-budget

      - name: update baseline
        run: |
          unsafe-budget update
          if [ -n "$(git status --porcelain unsafe-budget.lock)" ]; then
            git config user.name "github-actions[bot]"
            git config user.email "github-actions[bot]@users.noreply.github.com"
            git add unsafe-budget.lock
            git commit -m "chore: update unsafe-budget baseline"
            git push
          fi
```

## gitlab ci

```yaml
unsafe-budget:
  image: rust:latest
  script:
    - cargo install unsafe-budget
    - unsafe-budget check
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### with baseline update on main

```yaml
stages:
  - check
  - update

unsafe-budget-check:
  stage: check
  image: rust:latest
  script:
    - cargo install unsafe-budget
    - unsafe-budget check

unsafe-budget-update:
  stage: update
  image: rust:latest
  only:
    - main
  script:
    - cargo install unsafe-budget
    - unsafe-budget update
    - |
      if [ -n "$(git status --porcelain unsafe-budget.lock)" ]; then
        git config user.name "GitLab CI"
        git config user.email "ci@gitlab.com"
        git add unsafe-budget.lock
        git commit -m "chore: update unsafe-budget baseline"
        git push "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" HEAD:main
      fi
```

## caching

### github actions

```yaml
- uses: Swatinem/rust-cache@v2
```

### gitlab ci

```yaml
unsafe-budget:
  image: rust:latest
  cache:
    key: cargo
    paths:
      - .cargo/
      - target/
  variables:
    CARGO_HOME: $CI_PROJECT_DIR/.cargo
  script:
    - cargo install unsafe-budget
    - unsafe-budget check
```

## exit codes

| code | meaning |
|------|---------|
| 0 | check passed |
| 1 | runtime error |
| 2 | budget violation |

use exit code 2 to distinguish budget failures from other errors:

```yaml
# github actions
- name: check unsafe budget
  run: unsafe-budget check
  continue-on-error: false  # fail the job on violation
```

## tips

- commit `unsafe-budget.lock` to your repository
- run `unsafe-budget update` locally before first ci run
- use `--format json` for machine-readable output
- use `--workspace-only` to ignore dependencies
