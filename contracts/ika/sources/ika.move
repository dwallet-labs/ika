// Copyright (c) dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

/// The IKA for the Ika Protocol.
/// Coin<IKA> is the token used to pay for gas in Ika.
/// It has 9 decimals, and the smallest unit (10^-9) is called "INKU".
module ika::ika;

use sui::{coin, url};

// === Constants ===

/// The amount of INKU per IKA token based on the fact that INKU is
/// 10^-9 of a IKA token
const INKU_PER_IKA: u64 = 1_000_000_000;
const INITIAL_IKA_SUPPLY_TO_MINT: u64 = 10_000_000_000; // 10B IKA
const DECIMALS: u8 = 9;
const SYMBOL: vector<u8> = b"IKA";
const NAME: vector<u8> = b"IKA Token";
const DESCRIPTION: vector<u8> = b"Ika Protocol.";
const ICON_URL: vector<u8> =
    b"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAwIiBoZWlnaHQ9IjEwMDAiIHZpZXdCb3g9IjAgMCAxMDAwIDEwMDAiIGZpbGw9Im5vbmUiPiA8cmVjdCB3aWR0aD0iMTAwMCIgaGVpZ2h0PSIxMDAwIiBmaWxsPSIjRUUyQjVCIi8+IDxwYXRoIGQ9Ik02NzguNzQyIDU4OC45MzRWNDEwLjQ2N0M2NzguNzQyIDMxMS45MDIgNTk4Ljg0IDIzMiA1MDAuMjc1IDIzMlYyMzJDNDAxLjcxIDIzMiAzMjEuODA4IDMxMS45MDIgMzIxLjgwOCA0MTAuNDY3VjU4OC45MzQiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iNTcuMzIyOCIvPiA8cGF0aCBkPSJNNjc4Ljc0OCA1MjkuNDQxTDY3OC43NDggNTk4Ljg0NUM2NzguNzQ4IDYzNy4xNzYgNzA5LjgyMiA2NjguMjQ5IDc0OC4xNTIgNjY4LjI0OVY2NjguMjQ5Qzc4Ni40ODMgNjY4LjI0OSA4MTcuNTU2IDYzNy4xNzYgODE3LjU1NiA1OTguODQ1TDgxNy41NTYgNTI5LjQ0MSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI1Ny4zMjI4Ii8+IDxwYXRoIGQ9Ik01NzMuNDkxIDc2OC45MThMNTczLjQ5MSA2NjMuMTU5QzU3My40OTEgNjIyLjcyMyA1NDAuNzExIDU4OS45NDIgNTAwLjI3NCA1ODkuOTQyVjU4OS45NDJDNDU5LjgzNyA1ODkuOTQyIDQyNy4wNTYgNjIyLjcyMyA0MjcuMDU2IDY2My4xNTlMNDI3LjA1NiA3NjguOTE4IiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjU3LjMyMjgiLz4gPHBhdGggZD0iTTE4MyA1MjkuNDQxTDE4MyA1OTguODQ1QzE4MyA2MzcuMTc2IDIxNC4wNzMgNjY4LjI0OSAyNTIuNDA0IDY2OC4yNDlWNjY4LjI0OUMyOTAuNzM1IDY2OC4yNDkgMzIxLjgwOCA2MzcuMTc2IDMyMS44MDggNTk4Ljg0NUwzMjEuODA4IDUyOS40NDEiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iNTcuMzIyOCIvPiA8cGF0aCBkPSJNNTAwLjI3MiAzNzAuNzk4QzUzMy4xMjcgMzcwLjc5OCA1NTkuNzYxIDM5Ny40MzMgNTU5Ljc2MSA0MzAuMjg4QzU1OS43NjEgNDYzLjE0MiA1MzMuMTI3IDQ4OS43NzcgNTAwLjI3MiA0ODkuNzc3QzQ5NC4xNzQgNDg5Ljc3NyA0ODguMjkgNDg4Ljg1OCA0ODIuNzUxIDQ4Ny4xNTNDNDkzLjA4MiA0ODIuNDkgNTAwLjI3MiA0NzIuMSA1MDAuMjcyIDQ2MC4wMjlDNTAwLjI3MiA0NDMuNjAyIDQ4Ni45NTUgNDMwLjI4NSA0NzAuNTI4IDQzMC4yODVDNDU4LjQ1OCA0MzAuMjg1IDQ0OC4wNjcgNDM3LjQ3MyA0NDMuNDA0IDQ0Ny44MDJDNDQxLjcwMSA0NDIuMjY1IDQ0MC43ODMgNDM2LjM4MyA0NDAuNzgzIDQzMC4yODhDNDQwLjc4MyAzOTcuNDMzIDQ2Ny40MTcgMzcwLjc5OCA1MDAuMjcyIDM3MC43OThaIiBmaWxsPSJ3aGl0ZSIvPiA8L3N2Zz4=";

// === Structs ===

/// The OTW for the `IKA` coin.
public struct IKA has drop {}

// === Init Function ===

#[allow(deprecated_usage)]
fun init(otw: IKA, ctx: &mut TxContext) {
    let (mut treasury_cap, coin_metadata) = coin::create_currency(
        otw,
        DECIMALS, // decimals,
        SYMBOL, // symbol,
        NAME, // name,
        DESCRIPTION, // description,
        option::some(url::new_unsafe_from_bytes(ICON_URL)),
        ctx,
    );

    let total_supply_to_mint = INITIAL_IKA_SUPPLY_TO_MINT * INKU_PER_IKA;
    let minted_coin = treasury_cap.mint(total_supply_to_mint, ctx);

    transfer::public_transfer(treasury_cap, ctx.sender());
    transfer::public_freeze_object(coin_metadata);

    transfer::public_transfer(minted_coin, ctx.sender());
}

// === Public Functions ===

/// Number of INKU per IKA.
public fun inku_per_ika(): u64 {
    INKU_PER_IKA
}

// === Test only ===

#[test_only]
use sui::test_scenario;

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(IKA {}, ctx);
}

#[test]
fun test_init() {
    let user = @0xa11ce;
    let mut test = test_scenario::begin(user);
    init(IKA {}, test.ctx());
    test.next_tx(user);

    let treasury_cap = test.take_from_address<coin::TreasuryCap<IKA>>(user);
    let inku_per_ika = 10u64.pow(DECIMALS);
    let ika_supply = 10_000_000_000;
    assert!(treasury_cap.total_supply() == ika_supply * inku_per_ika);
    test.return_to_sender(treasury_cap);

    let coin_metadata = test.take_shared<coin::CoinMetadata<IKA>>();

    assert!(coin_metadata.get_decimals() == 9);
    assert!(coin_metadata.get_symbol() == b"IKA".to_ascii_string());
    assert!(coin_metadata.get_name() == b"IKA Token".to_string());
    assert!(coin_metadata.get_description() == b"Ika Protocol.".to_string());
    assert!(
        coin_metadata.get_icon_url() == option::some(url::new_unsafe_from_bytes(b"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxMDAwIiBoZWlnaHQ9IjEwMDAiIHZpZXdCb3g9IjAgMCAxMDAwIDEwMDAiIGZpbGw9Im5vbmUiPiA8cmVjdCB3aWR0aD0iMTAwMCIgaGVpZ2h0PSIxMDAwIiBmaWxsPSIjRUUyQjVCIi8+IDxwYXRoIGQ9Ik02NzguNzQyIDU4OC45MzRWNDEwLjQ2N0M2NzguNzQyIDMxMS45MDIgNTk4Ljg0IDIzMiA1MDAuMjc1IDIzMlYyMzJDNDAxLjcxIDIzMiAzMjEuODA4IDMxMS45MDIgMzIxLjgwOCA0MTAuNDY3VjU4OC45MzQiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iNTcuMzIyOCIvPiA8cGF0aCBkPSJNNjc4Ljc0OCA1MjkuNDQxTDY3OC43NDggNTk4Ljg0NUM2NzguNzQ4IDYzNy4xNzYgNzA5LjgyMiA2NjguMjQ5IDc0OC4xNTIgNjY4LjI0OVY2NjguMjQ5Qzc4Ni40ODMgNjY4LjI0OSA4MTcuNTU2IDYzNy4xNzYgODE3LjU1NiA1OTguODQ1TDgxNy41NTYgNTI5LjQ0MSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI1Ny4zMjI4Ii8+IDxwYXRoIGQ9Ik01NzMuNDkxIDc2OC45MThMNTczLjQ5MSA2NjMuMTU5QzU3My40OTEgNjIyLjcyMyA1NDAuNzExIDU4OS45NDIgNTAwLjI3NCA1ODkuOTQyVjU4OS45NDJDNDU5LjgzNyA1ODkuOTQyIDQyNy4wNTYgNjIyLjcyMyA0MjcuMDU2IDY2My4xNTlMNDI3LjA1NiA3NjguOTE4IiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjU3LjMyMjgiLz4gPHBhdGggZD0iTTE4MyA1MjkuNDQxTDE4MyA1OTguODQ1QzE4MyA2MzcuMTc2IDIxNC4wNzMgNjY4LjI0OSAyNTIuNDA0IDY2OC4yNDlWNjY4LjI0OUMyOTAuNzM1IDY2OC4yNDkgMzIxLjgwOCA2MzcuMTc2IDMyMS44MDggNTk4Ljg0NUwzMjEuODA4IDUyOS40NDEiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iNTcuMzIyOCIvPiA8cGF0aCBkPSJNNTAwLjI3MiAzNzAuNzk4QzUzMy4xMjcgMzcwLjc5OCA1NTkuNzYxIDM5Ny40MzMgNTU5Ljc2MSA0MzAuMjg4QzU1OS43NjEgNDYzLjE0MiA1MzMuMTI3IDQ4OS43NzcgNTAwLjI3MiA0ODkuNzc3QzQ5NC4xNzQgNDg5Ljc3NyA0ODguMjkgNDg4Ljg1OCA0ODIuNzUxIDQ4Ny4xNTNDNDkzLjA4MiA0ODIuNDkgNTAwLjI3MiA0NzIuMSA1MDAuMjcyIDQ2MC4wMjlDNTAwLjI3MiA0NDMuNjAyIDQ4Ni45NTUgNDMwLjI4NSA0NzAuNTI4IDQzMC4yODVDNDU4LjQ1OCA0MzAuMjg1IDQ0OC4wNjcgNDM3LjQ3MyA0NDMuNDA0IDQ0Ny44MDJDNDQxLjcwMSA0NDIuMjY1IDQ0MC43ODMgNDM2LjM4MyA0NDAuNzgzIDQzMC4yODhDNDQwLjc4MyAzOTcuNDMzIDQ2Ny40MTcgMzcwLjc5OCA1MDAuMjcyIDM3MC43OThaIiBmaWxsPSJ3aGl0ZSIvPiA8L3N2Zz4=")),
    );

    test_scenario::return_shared(coin_metadata);
    test.end();
}
