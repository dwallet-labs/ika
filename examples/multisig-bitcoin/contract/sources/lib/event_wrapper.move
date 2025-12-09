// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

module ika_btc_multisig::event_wrapper;

use sui::event::emit;

// === Structs ===

public struct Event<T: copy + drop>(T) has copy, drop;

// === Public Package Functions ===

public(package) fun emit_event<T: copy + drop>(event: T) {
  emit(Event(event));
}
