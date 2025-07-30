// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use include_directory::{Dir, DirEntry, include_directory};
use std::path::Path;
use tempfile::TempDir;

static CONTRACTS_DIR: Dir<'_> = include_directory!("$CARGO_MANIFEST_DIR/../../contracts");

pub fn save_contracts_to_temp_dir() -> anyhow::Result<TempDir> {
    let temp_dir =
        tempfile::tempdir().map_err(|e| anyhow::anyhow!("Failed to create temp dir: {}", e))?;
    let path = temp_dir.path();
    save_dir_entries(path, CONTRACTS_DIR.entries())?;
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
