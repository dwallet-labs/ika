// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use serde::Serialize;

/// Trait for CLI command outputs that support both human-readable and JSON formats.
///
/// All command response types should implement this trait to enable the global `--json` flag.
pub trait CommandOutput: Serialize {
    /// Print the output in human-readable format.
    fn print_human(&self);

    /// Print the output as JSON.
    fn print_json(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => println!("{json}"),
            Err(err) => eprintln!("Failed to serialize output as JSON: {err}"),
        }
    }

    /// Print the output, choosing format based on the `json` flag.
    fn print(&self, json: bool) {
        if json {
            self.print_json();
        } else {
            self.print_human();
        }
    }
}
