// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use include_directory::{Dir, DirEntry, include_directory};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use toml_edit::{DocumentMut, Item, Table, value};

static CONTRACTS_DIR: Dir<'_> = include_directory!("$CARGO_MANIFEST_DIR/../../contracts");
static TESTNET_CONTRACTS_DIR: Dir<'_> =
    include_directory!("$CARGO_MANIFEST_DIR/../../deployed_contracts/testnet");
static MAINNET_CONTRACTS_DIR: Dir<'_> =
    include_directory!("$CARGO_MANIFEST_DIR/../../deployed_contracts/mainnet");

pub fn save_contracts_to_temp_dir() -> anyhow::Result<TempDir> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {}", e))?;
    let path = temp_dir.path();
    save_dir_entries(path, CONTRACTS_DIR.entries())?;
    Ok(temp_dir)
}

pub fn save_testnet_contracts_to_temp_dir() -> anyhow::Result<TempDir> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {}", e))?;
    let path = temp_dir.path();
    save_dir_entries(path, TESTNET_CONTRACTS_DIR.entries())?;
    Ok(temp_dir)
}

pub fn save_mainnet_contracts_to_temp_dir() -> anyhow::Result<TempDir> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {}", e))?;
    let path = temp_dir.path();
    save_dir_entries(path, MAINNET_CONTRACTS_DIR.entries())?;
    Ok(temp_dir)
}

/// Unpack the bundled contracts and rewrite every `Move.toml` so the build does
/// not depend on Move's git-fetched system packages. We disable
/// `implicit-dependencies` and add explicit local-path deps on the provided Sui
/// framework and Move stdlib directories.
///
/// This exists for `cargo simtest`: move-package-alt's git fetcher uses
/// `tokio::process`, which msim does not emulate. Without this rewrite, any
/// Move build inside an msim runtime panics on the first git fetch.
pub fn save_contracts_to_temp_dir_for_simtest(
    sui_framework_path: &Path,
    move_stdlib_path: &Path,
) -> anyhow::Result<TempDir> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {}", e))?;
    let path = temp_dir.path();
    save_dir_entries(path, CONTRACTS_DIR.entries())?;
    rewrite_move_tomls_for_simtest(path, sui_framework_path, move_stdlib_path)?;
    Ok(temp_dir)
}

fn save_dir_entries<'a>(path: &Path, dir_entries: &'a [DirEntry<'a>]) -> anyhow::Result<()> {
    for dir_entry in dir_entries {
        match dir_entry {
            DirEntry::Dir(dir) => {
                save_dir_entries(path, dir.entries())?;
            }
            DirEntry::File(file) => {
                let file_path = path.join(file.path());
                std::fs::create_dir_all(Path::new(&file_path).parent().unwrap())
                    .map_err(|e| anyhow::anyhow!("Failed to create directory: {}", e))?;
                std::fs::write(file_path, file.contents())
                    .map_err(|e| anyhow::anyhow!("Failed to write file: {}", e))?;
            }
        }
    }
    Ok(())
}

fn rewrite_move_tomls_for_simtest(
    contracts_root: &Path,
    sui_framework_path: &Path,
    move_stdlib_path: &Path,
) -> anyhow::Result<()> {
    let mut move_tomls = Vec::new();
    collect_move_tomls(contracts_root, &mut move_tomls)?;

    for move_toml in move_tomls {
        let original = std::fs::read_to_string(&move_toml)?;
        let mut doc: DocumentMut = original
            .parse()
            .map_err(|e| anyhow::anyhow!("parsing {}: {}", move_toml.display(), e))?;

        let package = doc["package"]
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("{} missing [package]", move_toml.display()))?;
        package["implicit-dependencies"] = value(false);

        let deps_entry = doc
            .entry("dependencies")
            .or_insert(Item::Table(Table::new()));
        let deps = deps_entry.as_table_mut().ok_or_else(|| {
            anyhow::anyhow!("{} [dependencies] is not a table", move_toml.display())
        })?;
        deps["Sui"] = inline_local_dep(sui_framework_path);
        deps["MoveStdlib"] = inline_local_dep(move_stdlib_path);

        std::fs::write(&move_toml, doc.to_string())?;
    }
    Ok(())
}

fn collect_move_tomls(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_move_tomls(&path, out)?;
        } else if path.file_name().and_then(|n| n.to_str()) == Some("Move.toml") {
            out.push(path);
        }
    }
    Ok(())
}

fn inline_local_dep(path: &Path) -> Item {
    let mut table = toml_edit::InlineTable::new();
    table.insert(
        "local",
        toml_edit::Value::from(path.to_string_lossy().into_owned()),
    );
    Item::Value(toml_edit::Value::InlineTable(table))
}
