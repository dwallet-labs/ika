---
title: Module `ika::ika`
---

The IKA for the Ika Protocol.
Coin<IKA> is the token used to pay for gas in Ika.
It has 9 decimals, and the smallest unit (10^-9) is called "INKU".


-  [Struct `IKA`](#ika_ika_IKA)
-  [Constants](#@Constants_0)
-  [Function `init`](#ika_ika_init)
-  [Function `inku_per_ika`](#ika_ika_inku_per_ika)


<pre><code><b>use</b> <a href="../std/address.md#std_address">std::address</a>;
<b>use</b> <a href="../std/ascii.md#std_ascii">std::ascii</a>;
<b>use</b> <a href="../std/bcs.md#std_bcs">std::bcs</a>;
<b>use</b> <a href="../std/option.md#std_option">std::option</a>;
<b>use</b> <a href="../std/string.md#std_string">std::string</a>;
<b>use</b> <a href="../std/type_name.md#std_type_name">std::type_name</a>;
<b>use</b> <a href="../std/vector.md#std_vector">std::vector</a>;
<b>use</b> <a href="../sui/address.md#sui_address">sui::address</a>;
<b>use</b> <a href="../sui/bag.md#sui_bag">sui::bag</a>;
<b>use</b> <a href="../sui/balance.md#sui_balance">sui::balance</a>;
<b>use</b> <a href="../sui/coin.md#sui_coin">sui::coin</a>;
<b>use</b> <a href="../sui/config.md#sui_config">sui::config</a>;
<b>use</b> <a href="../sui/deny_list.md#sui_deny_list">sui::deny_list</a>;
<b>use</b> <a href="../sui/dynamic_field.md#sui_dynamic_field">sui::dynamic_field</a>;
<b>use</b> <a href="../sui/dynamic_object_field.md#sui_dynamic_object_field">sui::dynamic_object_field</a>;
<b>use</b> <a href="../sui/event.md#sui_event">sui::event</a>;
<b>use</b> <a href="../sui/hex.md#sui_hex">sui::hex</a>;
<b>use</b> <a href="../sui/object.md#sui_object">sui::object</a>;
<b>use</b> <a href="../sui/party.md#sui_party">sui::party</a>;
<b>use</b> <a href="../sui/table.md#sui_table">sui::table</a>;
<b>use</b> <a href="../sui/transfer.md#sui_transfer">sui::transfer</a>;
<b>use</b> <a href="../sui/tx_context.md#sui_tx_context">sui::tx_context</a>;
<b>use</b> <a href="../sui/types.md#sui_types">sui::types</a>;
<b>use</b> <a href="../sui/url.md#sui_url">sui::url</a>;
<b>use</b> <a href="../sui/vec_map.md#sui_vec_map">sui::vec_map</a>;
<b>use</b> <a href="../sui/vec_set.md#sui_vec_set">sui::vec_set</a>;
</code></pre>



<a name="ika_ika_IKA"></a>

## Struct `IKA`

The OTW for the <code><a href="../ika/ika.md#ika_ika_IKA">IKA</a></code> coin.


<pre><code><b>public</b> <b>struct</b> <a href="../ika/ika.md#ika_ika_IKA">IKA</a> <b>has</b> drop
</code></pre>



<details>
<summary>Fields</summary>


<dl>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="ika_ika_INKU_PER_IKA"></a>

The amount of INKU per IKA token based on the fact that INKU is
10^-9 of a IKA token


<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_INKU_PER_IKA">INKU_PER_IKA</a>: u64 = 1000000000;
</code></pre>



<a name="ika_ika_INITIAL_IKA_SUPPLY_TO_MINT"></a>



<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_INITIAL_IKA_SUPPLY_TO_MINT">INITIAL_IKA_SUPPLY_TO_MINT</a>: u64 = 10000000000;
</code></pre>



<a name="ika_ika_DECIMALS"></a>



<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_DECIMALS">DECIMALS</a>: u8 = 9;
</code></pre>



<a name="ika_ika_SYMBOL"></a>



<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_SYMBOL">SYMBOL</a>: vector&lt;u8&gt; = vector[73, 75, 65];
</code></pre>



<a name="ika_ika_NAME"></a>



<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_NAME">NAME</a>: vector&lt;u8&gt; = vector[73, 75, 65, 32, 84, 111, 107, 101, 110];
</code></pre>



<a name="ika_ika_DESCRIPTION"></a>



<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_DESCRIPTION">DESCRIPTION</a>: vector&lt;u8&gt; = vector[73, 107, 97, 32, 80, 114, 111, 116, 111, 99, 111, 108, 46];
</code></pre>



<a name="ika_ika_ICON_URL"></a>



<pre><code><b>const</b> <a href="../ika/ika.md#ika_ika_ICON_URL">ICON_URL</a>: vector&lt;u8&gt; = vector[100, 97, 116, 97, 58, 105, 109, 97, 103, 101, 47, 115, 118, 103, 43, 120, 109, 108, 59, 98, 97, 115, 101, 54, 52, 44, 80, 72, 78, 50, 90, 121, 66, 52, 98, 87, 120, 117, 99, 122, 48, 105, 97, 72, 82, 48, 99, 68, 111, 118, 76, 51, 100, 51, 100, 121, 53, 51, 77, 121, 53, 118, 99, 109, 99, 118, 77, 106, 65, 119, 77, 67, 57, 122, 100, 109, 99, 105, 73, 72, 100, 112, 90, 72, 82, 111, 80, 83, 73, 120, 77, 68, 65, 119, 73, 105, 66, 111, 90, 87, 108, 110, 97, 72, 81, 57, 73, 106, 69, 119, 77, 68, 65, 105, 73, 72, 90, 112, 90, 88, 100, 67, 98, 51, 103, 57, 73, 106, 65, 103, 77, 67, 65, 120, 77, 68, 65, 119, 73, 68, 69, 119, 77, 68, 65, 105, 73, 71, 90, 112, 98, 71, 119, 57, 73, 109, 53, 118, 98, 109, 85, 105, 80, 105, 65, 56, 99, 109, 86, 106, 100, 67, 66, 51, 97, 87, 82, 48, 97, 68, 48, 105, 77, 84, 65, 119, 77, 67, 73, 103, 97, 71, 86, 112, 90, 50, 104, 48, 80, 83, 73, 120, 77, 68, 65, 119, 73, 105, 66, 109, 97, 87, 120, 115, 80, 83, 73, 106, 82, 85, 85, 121, 81, 106, 86, 67, 73, 105, 56, 43, 73, 68, 120, 119, 89, 88, 82, 111, 73, 71, 81, 57, 73, 107, 48, 50, 78, 122, 103, 117, 78, 122, 81, 121, 73, 68, 85, 52, 79, 67, 52, 53, 77, 122, 82, 87, 78, 68, 69, 119, 76, 106, 81, 50, 78, 48, 77, 50, 78, 122, 103, 117, 78, 122, 81, 121, 73, 68, 77, 120, 77, 83, 52, 53, 77, 68, 73, 103, 78, 84, 107, 52, 76, 106, 103, 48, 73, 68, 73, 122, 77, 105, 65, 49, 77, 68, 65, 117, 77, 106, 99, 49, 73, 68, 73, 122, 77, 108, 89, 121, 77, 122, 74, 68, 78, 68, 65, 120, 76, 106, 99, 120, 73, 68, 73, 122, 77, 105, 65, 122, 77, 106, 69, 117, 79, 68, 65, 52, 73, 68, 77, 120, 77, 83, 52, 53, 77, 68, 73, 103, 77, 122, 73, 120, 76, 106, 103, 119, 79, 67, 65, 48, 77, 84, 65, 117, 78, 68, 89, 51, 86, 106, 85, 52, 79, 67, 52, 53, 77, 122, 81, 105, 73, 72, 78, 48, 99, 109, 57, 114, 90, 84, 48, 105, 100, 50, 104, 112, 100, 71, 85, 105, 73, 72, 78, 48, 99, 109, 57, 114, 90, 83, 49, 51, 97, 87, 82, 48, 97, 68, 48, 105, 78, 84, 99, 117, 77, 122, 73, 121, 79, 67, 73, 118, 80, 105, 65, 56, 99, 71, 70, 48, 97, 67, 66, 107, 80, 83, 74, 78, 78, 106, 99, 52, 76, 106, 99, 48, 79, 67, 65, 49, 77, 106, 107, 117, 78, 68, 81, 120, 84, 68, 89, 51, 79, 67, 52, 51, 78, 68, 103, 103, 78, 84, 107, 52, 76, 106, 103, 48, 78, 85, 77, 50, 78, 122, 103, 117, 78, 122, 81, 52, 73, 68, 89, 122, 78, 121, 52, 120, 78, 122, 89, 103, 78, 122, 65, 53, 76, 106, 103, 121, 77, 105, 65, 50, 78, 106, 103, 117, 77, 106, 81, 53, 73, 68, 99, 48, 79, 67, 52, 120, 78, 84, 73, 103, 78, 106, 89, 52, 76, 106, 73, 48, 79, 86, 89, 50, 78, 106, 103, 117, 77, 106, 81, 53, 81, 122, 99, 52, 78, 105, 52, 48, 79, 68, 77, 103, 78, 106, 89, 52, 76, 106, 73, 48, 79, 83, 65, 52, 77, 84, 99, 117, 78, 84, 85, 50, 73, 68, 89, 122, 78, 121, 52, 120, 78, 122, 89, 103, 79, 68, 69, 51, 76, 106, 85, 49, 78, 105, 65, 49, 79, 84, 103, 117, 79, 68, 81, 49, 84, 68, 103, 120, 78, 121, 52, 49, 78, 84, 89, 103, 78, 84, 73, 53, 76, 106, 81, 48, 77, 83, 73, 103, 99, 51, 82, 121, 98, 50, 116, 108, 80, 83, 74, 51, 97, 71, 108, 48, 90, 83, 73, 103, 99, 51, 82, 121, 98, 50, 116, 108, 76, 88, 100, 112, 90, 72, 82, 111, 80, 83, 73, 49, 78, 121, 52, 122, 77, 106, 73, 52, 73, 105, 56, 43, 73, 68, 120, 119, 89, 88, 82, 111, 73, 71, 81, 57, 73, 107, 48, 49, 78, 122, 77, 117, 78, 68, 107, 120, 73, 68, 99, 50, 79, 67, 52, 53, 77, 84, 104, 77, 78, 84, 99, 122, 76, 106, 81, 53, 77, 83, 65, 50, 78, 106, 77, 117, 77, 84, 85, 53, 81, 122, 85, 51, 77, 121, 52, 48, 79, 84, 69, 103, 78, 106, 73, 121, 76, 106, 99, 121, 77, 121, 65, 49, 78, 68, 65, 117, 78, 122, 69, 120, 73, 68, 85, 52, 79, 83, 52, 53, 78, 68, 73, 103, 78, 84, 65, 119, 76, 106, 73, 51, 78, 67, 65, 49, 79, 68, 107, 117, 79, 84, 81, 121, 86, 106, 85, 52, 79, 83, 52, 53, 78, 68, 74, 68, 78, 68, 85, 53, 76, 106, 103, 122, 78, 121, 65, 49, 79, 68, 107, 117, 79, 84, 81, 121, 73, 68, 81, 121, 78, 121, 52, 119, 78, 84, 89, 103, 78, 106, 73, 121, 76, 106, 99, 121, 77, 121, 65, 48, 77, 106, 99, 117, 77, 68, 85, 50, 73, 68, 89, 50, 77, 121, 52, 120, 78, 84, 108, 77, 78, 68, 73, 51, 76, 106, 65, 49, 78, 105, 65, 51, 78, 106, 103, 117, 79, 84, 69, 52, 73, 105, 66, 122, 100, 72, 74, 118, 97, 50, 85, 57, 73, 110, 100, 111, 97, 88, 82, 108, 73, 105, 66, 122, 100, 72, 74, 118, 97, 50, 85, 116, 100, 50, 108, 107, 100, 71, 103, 57, 73, 106, 85, 51, 76, 106, 77, 121, 77, 106, 103, 105, 76, 122, 52, 103, 80, 72, 66, 104, 100, 71, 103, 103, 90, 68, 48, 105, 84, 84, 69, 52, 77, 121, 65, 49, 77, 106, 107, 117, 78, 68, 81, 120, 84, 68, 69, 52, 77, 121, 65, 49, 79, 84, 103, 117, 79, 68, 81, 49, 81, 122, 69, 52, 77, 121, 65, 50, 77, 122, 99, 117, 77, 84, 99, 50, 73, 68, 73, 120, 78, 67, 52, 119, 78, 122, 77, 103, 78, 106, 89, 52, 76, 106, 73, 48, 79, 83, 65, 121, 78, 84, 73, 117, 78, 68, 65, 48, 73, 68, 89, 50, 79, 67, 52, 121, 78, 68, 108, 87, 78, 106, 89, 52, 76, 106, 73, 48, 79, 85, 77, 121, 79, 84, 65, 117, 78, 122, 77, 49, 73, 68, 89, 50, 79, 67, 52, 121, 78, 68, 107, 103, 77, 122, 73, 120, 76, 106, 103, 119, 79, 67, 65, 50, 77, 122, 99, 117, 77, 84, 99, 50, 73, 68, 77, 121, 77, 83, 52, 52, 77, 68, 103, 103, 78, 84, 107, 52, 76, 106, 103, 48, 78, 85, 119, 122, 77, 106, 69, 117, 79, 68, 65, 52, 73, 68, 85, 121, 79, 83, 52, 48, 78, 68, 69, 105, 73, 72, 78, 48, 99, 109, 57, 114, 90, 84, 48, 105, 100, 50, 104, 112, 100, 71, 85, 105, 73, 72, 78, 48, 99, 109, 57, 114, 90, 83, 49, 51, 97, 87, 82, 48, 97, 68, 48, 105, 78, 84, 99, 117, 77, 122, 73, 121, 79, 67, 73, 118, 80, 105, 65, 56, 99, 71, 70, 48, 97, 67, 66, 107, 80, 83, 74, 78, 78, 84, 65, 119, 76, 106, 73, 51, 77, 105, 65, 122, 78, 122, 65, 117, 78, 122, 107, 52, 81, 122, 85, 122, 77, 121, 52, 120, 77, 106, 99, 103, 77, 122, 99, 119, 76, 106, 99, 53, 79, 67, 65, 49, 78, 84, 107, 117, 78, 122, 89, 120, 73, 68, 77, 53, 78, 121, 52, 48, 77, 122, 77, 103, 78, 84, 85, 53, 76, 106, 99, 50, 77, 83, 65, 48, 77, 122, 65, 117, 77, 106, 103, 52, 81, 122, 85, 49, 79, 83, 52, 51, 78, 106, 69, 103, 78, 68, 89, 122, 76, 106, 69, 48, 77, 105, 65, 49, 77, 122, 77, 117, 77, 84, 73, 51, 73, 68, 81, 52, 79, 83, 52, 51, 78, 122, 99, 103, 78, 84, 65, 119, 76, 106, 73, 51, 77, 105, 65, 48, 79, 68, 107, 117, 78, 122, 99, 51, 81, 122, 81, 53, 78, 67, 52, 120, 78, 122, 81, 103, 78, 68, 103, 53, 76, 106, 99, 51, 78, 121, 65, 48, 79, 68, 103, 117, 77, 106, 107, 103, 78, 68, 103, 52, 76, 106, 103, 49, 79, 67, 65, 48, 79, 68, 73, 117, 78, 122, 85, 120, 73, 68, 81, 52, 78, 121, 52, 120, 78, 84, 78, 68, 78, 68, 107, 122, 76, 106, 65, 52, 77, 105, 65, 48, 79, 68, 73, 117, 78, 68, 107, 103, 78, 84, 65, 119, 76, 106, 73, 51, 77, 105, 65, 48, 78, 122, 73, 117, 77, 83, 65, 49, 77, 68, 65, 117, 77, 106, 99, 121, 73, 68, 81, 50, 77, 67, 52, 119, 77, 106, 108, 68, 78, 84, 65, 119, 76, 106, 73, 51, 77, 105, 65, 48, 78, 68, 77, 117, 78, 106, 65, 121, 73, 68, 81, 52, 78, 105, 52, 53, 78, 84, 85, 103, 78, 68, 77, 119, 76, 106, 73, 52, 78, 83, 65, 48, 78, 122, 65, 117, 78, 84, 73, 52, 73, 68, 81, 122, 77, 67, 52, 121, 79, 68, 86, 68, 78, 68, 85, 52, 76, 106, 81, 49, 79, 67, 65, 48, 77, 122, 65, 117, 77, 106, 103, 49, 73, 68, 81, 48, 79, 67, 52, 119, 78, 106, 99, 103, 78, 68, 77, 51, 76, 106, 81, 51, 77, 121, 65, 48, 78, 68, 77, 117, 78, 68, 65, 48, 73, 68, 81, 48, 78, 121, 52, 52, 77, 68, 74, 68, 78, 68, 81, 120, 76, 106, 99, 119, 77, 83, 65, 48, 78, 68, 73, 117, 77, 106, 89, 49, 73, 68, 81, 48, 77, 67, 52, 51, 79, 68, 77, 103, 78, 68, 77, 50, 76, 106, 77, 52, 77, 121, 65, 48, 78, 68, 65, 117, 78, 122, 103, 122, 73, 68, 81, 122, 77, 67, 52, 121, 79, 68, 104, 68, 78, 68, 81, 119, 76, 106, 99, 52, 77, 121, 65, 122, 79, 84, 99, 117, 78, 68, 77, 122, 73, 68, 81, 50, 78, 121, 52, 48, 77, 84, 99, 103, 77, 122, 99, 119, 76, 106, 99, 53, 79, 67, 65, 49, 77, 68, 65, 117, 77, 106, 99, 121, 73, 68, 77, 51, 77, 67, 52, 51, 79, 84, 104, 97, 73, 105, 66, 109, 97, 87, 120, 115, 80, 83, 74, 51, 97, 71, 108, 48, 90, 83, 73, 118, 80, 105, 65, 56, 76, 51, 78, 50, 90, 122, 52, 61];
</code></pre>



<a name="ika_ika_init"></a>

## Function `init`



<pre><code><b>fun</b> <a href="../ika/ika.md#ika_ika_init">init</a>(otw: <a href="../ika/ika.md#ika_ika_IKA">ika::ika::IKA</a>, ctx: &<b>mut</b> <a href="../sui/tx_context.md#sui_tx_context_TxContext">sui::tx_context::TxContext</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="../ika/ika.md#ika_ika_init">init</a>(otw: <a href="../ika/ika.md#ika_ika_IKA">IKA</a>, ctx: &<b>mut</b> TxContext) {
    <b>let</b> (<b>mut</b> treasury_cap, coin_metadata) = coin::create_currency(
        otw,
        <a href="../ika/ika.md#ika_ika_DECIMALS">DECIMALS</a>, // decimals,
        <a href="../ika/ika.md#ika_ika_SYMBOL">SYMBOL</a>, // symbol,
        <a href="../ika/ika.md#ika_ika_NAME">NAME</a>, // name,
        <a href="../ika/ika.md#ika_ika_DESCRIPTION">DESCRIPTION</a>, // description,
        option::some(url::new_unsafe_from_bytes(<a href="../ika/ika.md#ika_ika_ICON_URL">ICON_URL</a>)),
        ctx,
    );
    <b>let</b> total_supply_to_mint = <a href="../ika/ika.md#ika_ika_INITIAL_IKA_SUPPLY_TO_MINT">INITIAL_IKA_SUPPLY_TO_MINT</a> * <a href="../ika/ika.md#ika_ika_INKU_PER_IKA">INKU_PER_IKA</a>;
    <b>let</b> minted_coin = treasury_cap.mint(total_supply_to_mint, ctx);
    transfer::public_transfer(treasury_cap, ctx.sender());
    transfer::public_freeze_object(coin_metadata);
    transfer::public_transfer(minted_coin, ctx.sender());
}
</code></pre>



</details>

<a name="ika_ika_inku_per_ika"></a>

## Function `inku_per_ika`

Number of INKU per IKA.


<pre><code><b>public</b> <b>fun</b> <a href="../ika/ika.md#ika_ika_inku_per_ika">inku_per_ika</a>(): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="../ika/ika.md#ika_ika_inku_per_ika">inku_per_ika</a>(): u64 {
    <a href="../ika/ika.md#ika_ika_INKU_PER_IKA">INKU_PER_IKA</a>
}
</code></pre>



</details>
