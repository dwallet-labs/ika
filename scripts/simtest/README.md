Run ./install.sh to install the cargo-simtest command to your cargo directory.

## `config-patch`

`cargo simtest` injects the msim build settings with `--config` flags (see
`cargo-simtest`). `codecov.sh` cannot: it runs `cargo llvm-cov ... nextest`
directly, so it applies `config-patch` as a real diff instead and reverts it
afterwards. The two must stay in sync — same `--cfg msim`, same mysten-sim
`rev` for `tokio`/`futures-timer`.

`config-patch` is context-sensitive: it silently rots whenever the lines it
anchors on move. Regenerate it rather than hand-editing:

```bash
# from a clean tree
$EDITOR .cargo/config.toml Cargo.toml       # re-apply the two edits by hand
git diff -- .cargo/config.toml Cargo.toml > scripts/simtest/config-patch
git checkout -- .cargo/config.toml Cargo.toml
git apply --check ./scripts/simtest/config-patch   # must exit 0
```
