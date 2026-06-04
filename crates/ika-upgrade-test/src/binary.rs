// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Resolving a [`BinarySpec`] to a built `ika-validator` binary on disk.
//!
//! A spec can be a prebuilt path or a git ref (tag / sha / branch). Refs are
//! resolved to a commit, built once in an isolated `git worktree` using *that
//! commit's* pinned toolchain, and cached by sha so repeated runs (and the
//! `dev` side of every scenario) skip the build. This is the load-bearing
//! slice of a binary cache — not an LRU/`warm-cache` system. A ref that won't
//! build on its own toolchain fails loudly; the caller cherry-picks or skips.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// How to obtain an `ika-validator` binary for one side of a scenario.
#[derive(Clone, Debug)]
pub enum BinarySpec {
    /// A binary already on disk. Used as-is, never rebuilt.
    Path(PathBuf),
    /// A git tag, e.g. `mainnet-v1.1.8`.
    Tag(String),
    /// A full or abbreviated commit sha.
    Sha(String),
    /// A branch name, e.g. `dev`. Resolved to its current tip sha.
    Branch(String),
}

impl BinarySpec {
    /// Parse a CLI string into a spec. Heuristic, overridable by explicit
    /// `path:` / `tag:` / `sha:` / `branch:` prefixes:
    ///
    /// - contains a path separator or exists on disk -> `Path`
    /// - looks like a 7-40 char hex string -> `Sha`
    /// - otherwise -> `Branch`
    ///
    /// Tags are ambiguous with branches by name alone, so prefer the explicit
    /// `tag:` prefix (e.g. `tag:mainnet-v1.1.8`).
    pub fn parse(input: &str) -> Self {
        if let Some(rest) = input.strip_prefix("path:") {
            return BinarySpec::Path(PathBuf::from(rest));
        }
        if let Some(rest) = input.strip_prefix("tag:") {
            return BinarySpec::Tag(rest.to_string());
        }
        if let Some(rest) = input.strip_prefix("sha:") {
            return BinarySpec::Sha(rest.to_string());
        }
        if let Some(rest) = input.strip_prefix("branch:") {
            return BinarySpec::Branch(rest.to_string());
        }
        if input.contains('/') || input.contains('\\') || Path::new(input).exists() {
            return BinarySpec::Path(PathBuf::from(input));
        }
        let looks_like_sha =
            input.len() >= 7 && input.len() <= 40 && input.chars().all(|c| c.is_ascii_hexdigit());
        if looks_like_sha {
            BinarySpec::Sha(input.to_string())
        } else {
            BinarySpec::Branch(input.to_string())
        }
    }

    /// A short stable label for logs/labels.
    pub fn label(&self) -> String {
        match self {
            BinarySpec::Path(p) => format!("path:{}", p.display()),
            BinarySpec::Tag(t) => format!("tag:{t}"),
            BinarySpec::Sha(s) => format!("sha:{}", short_sha(s)),
            BinarySpec::Branch(b) => format!("branch:{b}"),
        }
    }
}

/// Resolves binary specs against a source checkout, caching built artifacts by
/// commit sha.
#[derive(Clone)]
pub struct BinaryResolver {
    /// Path to the source git repo to build from.
    repo: PathBuf,
    /// Cache root, default `~/.cache/ika-test-binaries`.
    cache_root: PathBuf,
}

impl BinaryResolver {
    pub fn new(repo: PathBuf, cache_root: PathBuf) -> Self {
        Self { repo, cache_root }
    }

    /// Default cache root: `$IKA_TEST_BINARIES_DIR` or `~/.cache/ika-test-binaries`.
    pub fn default_cache_root() -> PathBuf {
        if let Ok(dir) = std::env::var("IKA_TEST_BINARIES_DIR") {
            return PathBuf::from(dir);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".cache").join("ika-test-binaries")
    }

    /// Resolve a spec to a runnable `ika-validator` binary path, building and
    /// caching by sha if necessary.
    pub fn resolve(&self, spec: &BinarySpec) -> Result<PathBuf> {
        match spec {
            BinarySpec::Path(p) => {
                if !p.exists() {
                    bail!("binary path does not exist: {}", p.display());
                }
                Ok(p.clone())
            }
            BinarySpec::Tag(r) | BinarySpec::Branch(r) | BinarySpec::Sha(r) => {
                let sha = self.rev_parse(r)?;
                self.build_at_sha(&sha)
            }
        }
    }

    /// `git rev-parse <ref>^{commit}` inside the source repo.
    fn rev_parse(&self, git_ref: &str) -> Result<String> {
        let out = self
            .git(&["rev-parse", "--verify", &format!("{git_ref}^{{commit}}")])
            .with_context(|| format!("git rev-parse {git_ref}"))?;
        let sha = out.trim().to_string();
        if sha.len() < 7 {
            bail!("unexpected rev-parse output for {git_ref}: {sha:?}");
        }
        Ok(sha)
    }

    /// Build `ika-validator` at `sha` in an isolated worktree, then atomically
    /// publish into the sha-keyed cache dir. Returns the cached binary path.
    /// A cache hit (sha dir already present) skips the build entirely.
    fn build_at_sha(&self, sha: &str) -> Result<PathBuf> {
        let final_dir = self.cache_root.join("by-sha").join(sha);
        let binary = final_dir.join("ika-validator");
        if binary.exists() {
            tracing::info!(sha = %short_sha(sha), "binary cache hit");
            return Ok(binary);
        }
        std::fs::create_dir_all(&self.cache_root)?;

        // Build in a throwaway worktree so the caller's checkout is untouched
        // and we compile exactly the code at `sha` (its own rust-toolchain.toml
        // is honored because cargo reads it from the worktree root).
        let worktree = self
            .cache_root
            .join("worktrees")
            .join(format!("build-{}", short_sha(sha)));
        if worktree.exists() {
            // Stale worktree from an aborted run; remove its registration.
            let _ = self.git(&["worktree", "remove", "--force", &worktree.to_string_lossy()]);
        }
        std::fs::create_dir_all(worktree.parent().unwrap())?;
        self.git(&[
            "worktree",
            "add",
            "--force",
            "--detach",
            &worktree.to_string_lossy(),
            sha,
        ])
        .with_context(|| format!("git worktree add for {sha}"))?;

        tracing::info!(sha = %short_sha(sha), "building ika-validator (cache miss)");
        // `--no-default-features` drops `ika-node`'s only default feature,
        // `enforce-minimum-cpu`, which otherwise panics the validator on hosts
        // with < 16 cores. The harness must run on ordinary dev machines.
        let status = Command::new("cargo")
            .current_dir(&worktree)
            .args([
                "build",
                "--release",
                "-p",
                "ika-node",
                "--no-default-features",
                "--bin",
                "ika-validator",
            ])
            .status()
            .context("spawn cargo build")?;
        if !status.success() {
            let _ = self.git(&["worktree", "remove", "--force", &worktree.to_string_lossy()]);
            bail!(
                "cargo build of ika-validator at {} failed (toolchain mismatch? \
                 cherry-pick or use a prebuilt path: spec)",
                short_sha(sha)
            );
        }

        let built = worktree.join("target/release/ika-validator");
        if !built.exists() {
            bail!("build succeeded but {} is missing", built.display());
        }

        // Publish atomically: copy into a temp dir, then rename into place. A
        // concurrent builder that wins the race leaves `final_dir` present and
        // our rename is a harmless no-op fallback to the cache-hit path.
        let staging = self.cache_root.join("staging").join(format!(
            "{}-{}",
            short_sha(sha),
            std::process::id()
        ));
        std::fs::create_dir_all(&staging)?;
        std::fs::copy(&built, staging.join("ika-validator"))?;
        std::fs::create_dir_all(final_dir.parent().unwrap())?;
        match std::fs::rename(&staging, &final_dir) {
            Ok(()) => {}
            Err(_) if binary.exists() => {
                let _ = std::fs::remove_dir_all(&staging);
            }
            Err(e) => return Err(e).context("publish built binary into cache"),
        }

        let _ = self.git(&["worktree", "remove", "--force", &worktree.to_string_lossy()]);
        Ok(binary)
    }

    fn git(&self, args: &[&str]) -> Result<String> {
        let out = Command::new("git")
            .current_dir(&self.repo)
            .args(args)
            .output()
            .with_context(|| format!("spawn git {args:?}"))?;
        if !out.status.success() {
            bail!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

fn short_sha(sha: &str) -> &str {
    &sha[..sha.len().min(12)]
}
