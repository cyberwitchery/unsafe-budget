# agent guidelines

guidelines for ai agents working on this codebase.

## constraints

- do not introduce new dependencies without discussion
- do not refactor code outside the scope of the task
- do not add features beyond what was requested
- preserve existing error handling patterns
- maintain deterministic output ordering

## workflow

1. understand the task fully before making changes
2. read relevant existing code first
3. make minimal, focused changes
4. add tests for new functionality
5. run `./ci.sh` before submitting

## rust-specific

- use `thiserror` for error types
- use `BTreeMap`/`BTreeSet` for deterministic iteration
- prefer `&str` over `String` in function signatures where possible
- document public items with examples
- use `#[cfg(test)] mod tests` for unit tests

## security considerations

this is a security tool. when modifying:

- never execute untrusted code from analyzed projects
- validate all external tool output before parsing
- do not leak sensitive paths in error messages
- sanitize output that may be logged

## output format

- text output should be human-readable tables
- json output must be valid and parseable
- maintain backwards compatibility in json schema
- use stable field ordering (alphabetical or semantic)

## testing

- unit tests go in the same file as the code
- integration tests use fixtures in `tests/fixtures/`
- test both success and error cases
- test with `--all-features` and without
