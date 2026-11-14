//! the unit a file belongs to, named from the file's path.

use std::path::Path;

/// extract a unit name from an artifact's file path.
///
/// the directory before the `src` component nearest the file names the crate
/// (`crate_name/src/lib.rs` → `crate_name`), falling back to the first
/// directory component when there is none, or `"unknown"` for bare filenames.
pub(crate) fn extract_unit_name(file: &str) -> String {
    let path_str = file.strip_prefix("file://").unwrap_or(file);
    let components = normal_components(path_str);

    // need at least a directory and a filename.
    if components.len() < 2 {
        return "unknown".into();
    }

    let dirs = &components[..components.len() - 1];

    match dirs.iter().rposition(|dir| dir == "src") {
        Some(i) if i > 0 => dirs[i - 1].clone(),
        _ => dirs[0].clone(),
    }
}

/// the dependency a file under a dependency cache or `vendor/` belongs to; `None` for a workspace file.
pub(crate) fn dependency_unit_name(located: &str) -> Option<String> {
    let components = normal_components(located);
    let (file_name, dirs) = components.split_last()?;
    let is_go = Path::new(file_name)
        .extension()
        .is_some_and(|ext| ext == "go");
    registry_crate(dirs)
        .or_else(|| git_checkout_crate(dirs))
        .or_else(|| cached_module(located))
        .or_else(|| {
            if is_go || in_go_vendor_tree(located) {
                vendored_package(located)
            } else {
                vendored_crate(located)
            }
        })
}

/// whether the directory below the first `vendor/` is a go module host: `github.com`, not `lua5.4`.
fn in_go_vendor_tree(located: &str) -> bool {
    below_first_vendor(located)
        .and_then(|below| below.split_once('/'))
        .is_some_and(|(dir, _)| {
            dir.rsplit_once('.')
                .is_some_and(|(_, label)| label.starts_with(|c: char| c.is_ascii_lowercase()))
                && !has_crate_version(dir)
        })
}

/// `serde-1.0.200`: a `cargo vendor` crate directory with a `-<version>` suffix.
fn has_crate_version(dir: &str) -> bool {
    let before_dot = dir.split('.').next().unwrap_or(dir);
    let Some(dash) = before_dot.rfind('-') else {
        return false;
    };
    let mut parts = dir[dash + 1..].splitn(3, '.');
    let number = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    };
    number(parts.next())
        && number(parts.next())
        && parts
            .next()
            .is_some_and(|patch| patch.starts_with(|c: char| c.is_ascii_digit()))
}

fn normal_components(path: &str) -> Vec<String> {
    Path::new(path)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

fn registry_crate(dirs: &[String]) -> Option<String> {
    dirs.windows(4)
        .find(|w| w[0] == "registry" && w[1] == "src" && strip_cargo_hash(&w[2]).is_some())
        .map(|w| strip_crate_version(&w[3]).to_string())
}

fn git_checkout_crate(dirs: &[String]) -> Option<String> {
    let start = dirs
        .windows(3)
        .position(|w| w[0] == "git" && w[1] == "checkouts" && strip_cargo_hash(&w[2]).is_some())?;
    let [checkout, _rev, below @ ..] = &dirs[start + 2..] else {
        return None;
    };
    match below.iter().rposition(|dir| dir == "src") {
        Some(i) if i > 0 => Some(below[i - 1].clone()),
        _ => strip_cargo_hash(checkout).map(str::to_string),
    }
}

/// `my_crate-0123456789abcdef` → `my_crate`: cargo's `<name>-<16 hex digits>[-shallow]` directories.
fn strip_cargo_hash(dir: &str) -> Option<&str> {
    let dir = dir.strip_suffix("-shallow").unwrap_or(dir);
    let (name, hash) = dir.rsplit_once('-')?;
    (hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(name)
}

fn vendored_crate(located: &str) -> Option<String> {
    let below = below_first_vendor(located)?;
    below.split('/').next().map(str::to_string)
}

/// `serde-1.0.200` → `serde`: the version follows the last `-` before the first `.`.
fn strip_crate_version(dir: &str) -> &str {
    let before_dot = dir.split('.').next().unwrap_or(dir);
    match before_dot.rfind('-') {
        Some(i) if dir[i + 1..].starts_with(|c: char| c.is_ascii_digit()) => &dir[..i],
        _ => dir,
    }
}

/// the package directory below the innermost `vendor` directory in `path`
/// (`…/vendor/github.com/pkg/errors/errors.go` → `github.com/pkg/errors`).
fn vendored_package(path: &str) -> Option<String> {
    let after_vendor = match path.rfind("/vendor/") {
        Some(idx) => &path[idx + 8..],
        None => path.strip_prefix("vendor/")?,
    };
    if let Some(end) = after_vendor.rfind('/') {
        return Some(after_vendor[..end].to_string());
    }
    Some(after_vendor.to_string())
}

/// the part of `path` below its first `vendor` directory.
fn below_first_vendor(path: &str) -> Option<&str> {
    path.strip_prefix("vendor/")
        .or_else(|| path.split_once("/vendor/").map(|(_, below)| below))
}

/// the module a file in the go module cache belongs to, without its version
/// (`…/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go` → `github.com/BurntSushi/toml`).
/// the module path starts below `pkg/mod`, else at the first directory a module path can start at.
fn cached_module(path: &str) -> Option<String> {
    let mut dirs: Vec<&str> = path.split('/').collect();
    dirs.pop();
    let (root, last) = dirs.iter().enumerate().find_map(|(i, dir)| {
        let (last, version) = dir.split_once('@')?;
        let is_version = version
            .strip_prefix('v')
            .is_some_and(|v| v.starts_with(|c: char| c.is_ascii_digit()));
        is_version.then_some((i, last))
    })?;
    let below_pkg_mod = dirs[..root]
        .windows(2)
        .position(|w| w == ["pkg", "mod"])
        .map(|i| i + 2);
    dirs.truncate(root);
    dirs.push(last);
    let start = below_pkg_mod.or_else(|| (0..dirs.len()).find(|&i| is_module_path(&dirs[i..])))?;
    let escaped = dirs[start..].join("/");
    Some(unescape_module_path(&escaped).unwrap_or(escaped))
}

/// whether `elems` pass golang.org/x/mod's `CheckPath` character rules as an escaped module path.
fn is_module_path(elems: &[&str]) -> bool {
    let Some(first) = elems.first() else {
        return false;
    };
    first.contains('.')
        && !first.starts_with('-')
        && first
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
        && elems.iter().all(|elem| {
            !elem.starts_with('.')
                && elem.bytes().all(
                    |b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' | b'!'),
                )
        })
}

/// `unescapeString` from golang.org/x/mod/module: `!` + a lower-case letter is
/// that letter upper-cased; `None` for an invalid escaped path.
fn unescape_module_path(escaped: &str) -> Option<String> {
    let mut path = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        match c {
            '!' => path.push(
                chars
                    .next()
                    .filter(char::is_ascii_lowercase)?
                    .to_ascii_uppercase(),
            ),
            c if c.is_ascii_uppercase() || !c.is_ascii() => return None,
            c => path.push(c),
        }
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_unit_name() {
        let cases = [
            ("src/lib.rs", "src"),
            ("my_crate/src/lib.rs", "my_crate"),
            ("my_crate/src/foo/bar.rs", "my_crate"),
            ("file://project/my_crate/src/lib.rs", "my_crate"),
            ("lib.rs", "unknown"),
            ("crate_a/lib.rs", "crate_a"),
            // the nearest src wins
            ("/home/u/src/proj/crates/x/src/lib.rs", "x"),
            ("/home/u/src/proj/src/a/b.rs", "proj"),
        ];
        for (path, name) in cases {
            assert_eq!(extract_unit_name(path), name, "{path}");
        }
    }

    #[test]
    fn test_dependency_caches_are_read_from_their_layout_under_any_root() {
        let registry = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let cases = [
            (format!("{registry}/serde-1.0.200/src/lib.rs"), Some("serde")),
            (format!("{registry}/proc-macro2-1.0.86/build.rs"), Some("proc-macro2")),
            (format!("{registry}/foo-2d-0.1.0-alpha.1/src/lib.rs"), Some("foo-2d")),
            (
                format!("{registry}/windows_x86_64_gnu-0.52.6/src/lib.rs"),
                Some("windows_x86_64_gnu"),
            ),
            (
                "/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libc-0.2.155/src/unix/mod.rs".into(),
                Some("libc"),
            ),
            (
                "C:/cargo/registry/src/github.com-1ecc6299db9ec823/libc-0.2.155/src/lib.rs".into(),
                Some("libc"),
            ),
            (
                "/home/u/.cargo/registry/src/github.com-1ecc6299db9ec823-shallow/serde-1.0.200/src/lib.rs".into(),
                Some("serde"),
            ),
            (
                "/usr/local/cargo/git/checkouts/my_crate-fedcba9876543210/9f8e7d6/src/lib.rs".into(),
                Some("my_crate"),
            ),
            ("crates/registry/src/backend-db/pg/mod.rs".into(), None),
            (
                "web/node_modules/.pnpm/socket.io@4.7.2/node_modules/socket.io/index.js".into(),
                None,
            ),
            ("vendor-tools/gen.go".into(), None),
        ];
        for (path, name) in cases {
            assert_eq!(dependency_unit_name(&path).as_deref(), name, "{path}");
        }
    }

    #[test]
    fn test_the_first_directory_below_vendor_tells_a_go_tree_from_a_cargo_one() {
        for (path, unit) in [
            (
                "/home/u/proj/vendor/github.com/foo/bar/bar.c",
                "github.com/foo/bar",
            ),
            (
                "/home/u/proj/vendor/gopkg.in/yaml.v3/yaml.h",
                "gopkg.in/yaml.v3",
            ),
            (
                "/home/u/proj/vendor/git-01.corp.example.com/x/y/y.s",
                "git-01.corp.example.com/x/y",
            ),
            ("/home/u/proj/vendor/serde/src/de/mod.rs", "serde"),
            (
                "/home/u/proj/vendor/foo-sys/vendor/lua5.4/lapi.c",
                "foo-sys",
            ),
            (
                "/home/u/proj/vendor/serde-1.0.200/src/de/mod.rs",
                "serde-1.0.200",
            ),
            (
                "/home/u/proj/vendor/foo-0.1.0-alpha.1/src/lib.rs",
                "foo-0.1.0-alpha.1",
            ),
            (
                "/home/u/proj/vendor/windows_x86_64_gnu-0.48.5/lib/x.a",
                "windows_x86_64_gnu-0.48.5",
            ),
            (
                "/home/u/proj/vendor/foo-sys/vendor/github.com/a/b/b.c",
                "foo-sys",
            ),
            (
                "/home/u/proj/vendor/foo-1.0.0-beta.rc/src/lib.rs",
                "foo-1.0.0-beta.rc",
            ),
            ("/home/u/proj/vendor/lua5.4/src/lapi.c", "lua5.4"),
            (
                "/home/u/proj/vendor/mbedtls-2.28/library/aes.c",
                "mbedtls-2.28",
            ),
            ("/home/u/proj/vendor/x.c", "x.c"),
        ] {
            assert_eq!(dependency_unit_name(path).as_deref(), Some(unit), "{path}");
        }
    }

    #[test]
    fn test_vendored_package_is_below_the_innermost_vendor_directory() {
        for (path, package) in [
            (
                "/home/user/myproject/vendor/github.com/pkg/errors/errors.go",
                "github.com/pkg/errors",
            ),
            ("/home/user/myproject/vendor/errors/errors.go", "errors"),
            (
                "/home/user/myproject/vendor/github.com/a/tool/vendor/github.com/b/lib/lib.go",
                "github.com/b/lib",
            ),
            (
                "vendor/github.com/pkg/errors/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "vendor/github.com/a/tool/vendor/github.com/b/lib/lib.go",
                "github.com/b/lib",
            ),
        ] {
            assert_eq!(vendored_package(path), Some(package.into()), "{path}");
        }
    }

    #[test]
    fn test_cached_module() {
        for (path, module) in [
            (
                "/home/user/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "/srv/vendor/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "/home/u/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go",
                "github.com/BurntSushi/toml",
            ),
            (
                "/cache/gomod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "/home/first.last/.cache/gomod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
            (
                "/home/first.last/go/pkg/mod/github.com/pkg/errors@v0.9.1/errors.go",
                "github.com/pkg/errors",
            ),
        ] {
            assert_eq!(cached_module(path), Some(module.into()), "{path}");
        }
    }

    #[test]
    fn test_cached_module_keeps_an_invalid_escaped_path() {
        for module in [
            "github.com/!burnt!sushi/Toml",
            "github.com/!burnt!!sushi/toml",
            "github.com/!burnt!1sushi/toml",
            "github.com/!burnt!ésushi/toml",
            "github.com/!burnt/brûlé",
            "github.com/!burnt/toml!",
        ] {
            let path = format!("/home/u/go/pkg/mod/{module}@v1.3.2/decode.go");
            assert_eq!(cached_module(&path), Some(module.into()), "{module}");
        }
    }
}
