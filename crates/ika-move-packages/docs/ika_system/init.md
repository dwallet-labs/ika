---
title: Module `(ika_system=0x0)::init`
---



-  [Struct `INIT`](#(ika_system=0x0)_init_INIT)
-  [Struct `InitCap`](#(ika_system=0x0)_init_InitCap)
-  [Constants](#@Constants_0)
-  [Function `init`](#(ika_system=0x0)_init_init)
-  [Function `initialize`](#(ika_system=0x0)_init_initialize)


<pre><code><b>use</b> (ika=0x0)::ika;
<b>use</b> (ika_common=0x0)::bls_committee;
<b>use</b> (ika_common=0x0)::class_groups_public_key_and_proof;
<b>use</b> (ika_common=0x0)::extended_field;
<b>use</b> (ika_common=0x0)::multiaddr;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/advance_epoch_approver.md#(ika_system=0x0)_advance_epoch_approver">advance_epoch_approver</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/display.md#(ika_system=0x0)_display">display</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/pending_active_set.md#(ika_system=0x0)_pending_active_set">pending_active_set</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/pending_values.md#(ika_system=0x0)_pending_values">pending_values</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/protocol_cap.md#(ika_system=0x0)_protocol_cap">protocol_cap</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/protocol_treasury.md#(ika_system=0x0)_protocol_treasury">protocol_treasury</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/staked_ika.md#(ika_system=0x0)_staked_ika">staked_ika</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/system.md#(ika_system=0x0)_system">system</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/system_current_status_info.md#(ika_system=0x0)_system_current_status_info">system_current_status_info</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/system_inner.md#(ika_system=0x0)_system_inner">system_inner</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/token_exchange_rate.md#(ika_system=0x0)_token_exchange_rate">token_exchange_rate</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/validator.md#(ika_system=0x0)_validator">validator</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/validator_cap.md#(ika_system=0x0)_validator_cap">validator_cap</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/validator_info.md#(ika_system=0x0)_validator_info">validator_info</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/validator_metadata.md#(ika_system=0x0)_validator_metadata">validator_metadata</a>;
<b>use</b> (ika_system=0x0)::<a href="../ika_system/validator_set.md#(ika_system=0x0)_validator_set">validator_set</a>;
<b>use</b> <a href="../std/address.md#std_address">std::address</a>;
<b>use</b> <a href="../std/ascii.md#std_ascii">std::ascii</a>;
<b>use</b> <a href="../std/bcs.md#std_bcs">std::bcs</a>;
<b>use</b> <a href="../std/option.md#std_option">std::option</a>;
<b>use</b> <a href="../std/string.md#std_string">std::string</a>;
<b>use</b> <a href="../std/type_name.md#std_type_name">std::type_name</a>;
<b>use</b> <a href="../std/u64.md#std_u64">std::u64</a>;
<b>use</b> <a href="../std/vector.md#std_vector">std::vector</a>;
<b>use</b> <a href="../sui/address.md#sui_address">sui::address</a>;
<b>use</b> <a href="../sui/bag.md#sui_bag">sui::bag</a>;
<b>use</b> <a href="../sui/balance.md#sui_balance">sui::balance</a>;
<b>use</b> <a href="../sui/bcs.md#sui_bcs">sui::bcs</a>;
<b>use</b> <a href="../sui/bls12381.md#sui_bls12381">sui::bls12381</a>;
<b>use</b> <a href="../sui/clock.md#sui_clock">sui::clock</a>;
<b>use</b> <a href="../sui/coin.md#sui_coin">sui::coin</a>;
<b>use</b> <a href="../sui/config.md#sui_config">sui::config</a>;
<b>use</b> <a href="../sui/deny_list.md#sui_deny_list">sui::deny_list</a>;
<b>use</b> <a href="../sui/display.md#sui_display">sui::display</a>;
<b>use</b> <a href="../sui/dynamic_field.md#sui_dynamic_field">sui::dynamic_field</a>;
<b>use</b> <a href="../sui/dynamic_object_field.md#sui_dynamic_object_field">sui::dynamic_object_field</a>;
<b>use</b> <a href="../sui/event.md#sui_event">sui::event</a>;
<b>use</b> <a href="../sui/group_ops.md#sui_group_ops">sui::group_ops</a>;
<b>use</b> <a href="../sui/hex.md#sui_hex">sui::hex</a>;
<b>use</b> <a href="../sui/object.md#sui_object">sui::object</a>;
<b>use</b> <a href="../sui/object_bag.md#sui_object_bag">sui::object_bag</a>;
<b>use</b> <a href="../sui/object_table.md#sui_object_table">sui::object_table</a>;
<b>use</b> <a href="../sui/package.md#sui_package">sui::package</a>;
<b>use</b> <a href="../sui/party.md#sui_party">sui::party</a>;
<b>use</b> <a href="../sui/table.md#sui_table">sui::table</a>;
<b>use</b> <a href="../sui/table_vec.md#sui_table_vec">sui::table_vec</a>;
<b>use</b> <a href="../sui/transfer.md#sui_transfer">sui::transfer</a>;
<b>use</b> <a href="../sui/tx_context.md#sui_tx_context">sui::tx_context</a>;
<b>use</b> <a href="../sui/types.md#sui_types">sui::types</a>;
<b>use</b> <a href="../sui/url.md#sui_url">sui::url</a>;
<b>use</b> <a href="../sui/vec_map.md#sui_vec_map">sui::vec_map</a>;
<b>use</b> <a href="../sui/vec_set.md#sui_vec_set">sui::vec_set</a>;
</code></pre>



<a name="(ika_system=0x0)_init_INIT"></a>

## Struct `INIT`

The OTW to create <code>Publisher</code> and <code>Display</code> objects.


<pre><code><b>public</b> <b>struct</b> <a href="../ika_system/init.md#(ika_system=0x0)_init_INIT">INIT</a> <b>has</b> drop
</code></pre>



<details>
<summary>Fields</summary>


<dl>
</dl>


</details>

<a name="(ika_system=0x0)_init_InitCap"></a>

## Struct `InitCap`

Must only be created by <code><a href="../ika_system/init.md#(ika_system=0x0)_init">init</a></code>.


<pre><code><b>public</b> <b>struct</b> <a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">InitCap</a> <b>has</b> key, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>id: <a href="../sui/object.md#sui_object_UID">sui::object::UID</a></code>
</dt>
<dd>
</dd>
<dt>
<code>publisher: <a href="../sui/package.md#sui_package_Publisher">sui::package::Publisher</a></code>
</dt>
<dd>
</dd>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="(ika_system=0x0)_init_EInvalidUpgradeCap"></a>

The provided upgrade cap does not belong to this package.


<pre><code><b>const</b> <a href="../ika_system/init.md#(ika_system=0x0)_init_EInvalidUpgradeCap">EInvalidUpgradeCap</a>: u64 = 1;
</code></pre>



<a name="(ika_system=0x0)_init_init"></a>

## Function `init`

Init function, creates an init cap and transfers it to the sender.
This allows the sender to call the function to actually initialize the system
with the corresponding parameters. Once that function is called, the cap is destroyed.


<pre><code><b>fun</b> <a href="../ika_system/init.md#(ika_system=0x0)_init">init</a>(otw: (ika_system=0x0)::<a href="../ika_system/init.md#(ika_system=0x0)_init_INIT">init::INIT</a>, ctx: &<b>mut</b> <a href="../sui/tx_context.md#sui_tx_context_TxContext">sui::tx_context::TxContext</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="../ika_system/init.md#(ika_system=0x0)_init">init</a>(otw: <a href="../ika_system/init.md#(ika_system=0x0)_init_INIT">INIT</a>, ctx: &<b>mut</b> TxContext) {
    <b>let</b> id = object::new(ctx);
    <b>let</b> publisher = package::claim(otw, ctx);
    <b>let</b> init_cap = <a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">InitCap</a> { id, publisher };
    transfer::transfer(init_cap, ctx.sender());
}
</code></pre>



</details>

<a name="(ika_system=0x0)_init_initialize"></a>

## Function `initialize`

Function to initialize ika and share the system object.
This can only be called once, after which the <code><a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">InitCap</a></code> is destroyed.


<pre><code><b>public</b> <b>fun</b> <a href="../ika_system/init.md#(ika_system=0x0)_init_initialize">initialize</a>(init_cap: (ika_system=0x0)::<a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">init::InitCap</a>, ika_upgrade_cap: <a href="../sui/package.md#sui_package_UpgradeCap">sui::package::UpgradeCap</a>, ika_system_upgrade_cap: <a href="../sui/package.md#sui_package_UpgradeCap">sui::package::UpgradeCap</a>, protocol_treasury_cap: <a href="../sui/coin.md#sui_coin_TreasuryCap">sui::coin::TreasuryCap</a>&lt;(ika=0x0)::ika::IKA&gt;, protocol_version: u64, chain_start_timestamp_ms: u64, epoch_duration_ms: u64, stake_subsidy_start_epoch: u64, stake_subsidy_rate: u16, stake_subsidy_period_length: u64, min_validator_count: u64, max_validator_count: u64, min_validator_joining_stake: u64, reward_slashing_rate: u16, staked_ika_image_url: <a href="../std/string.md#std_string_String">std::string::String</a>, ctx: &<b>mut</b> <a href="../sui/tx_context.md#sui_tx_context_TxContext">sui::tx_context::TxContext</a>): (ika_system=0x0)::<a href="../ika_system/protocol_cap.md#(ika_system=0x0)_protocol_cap_ProtocolCap">protocol_cap::ProtocolCap</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="../ika_system/init.md#(ika_system=0x0)_init_initialize">initialize</a>(
    init_cap: <a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">InitCap</a>,
    ika_upgrade_cap: UpgradeCap,
    ika_system_upgrade_cap: UpgradeCap,
    protocol_treasury_cap: TreasuryCap&lt;IKA&gt;,
    protocol_version: u64,
    chain_start_timestamp_ms: u64,
    epoch_duration_ms: u64,
    // Stake Subsidy parameters
    stake_subsidy_start_epoch: u64,
    stake_subsidy_rate: u16,
    stake_subsidy_period_length: u64,
    // Validator committee parameters
    min_validator_count: u64,
    max_validator_count: u64,
    min_validator_joining_stake: u64,
    reward_slashing_rate: u16,
    // Display parameters
    staked_ika_image_url: String,
    ctx: &<b>mut</b> TxContext,
): ProtocolCap {
    <b>let</b> <a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">InitCap</a> { id, publisher } = init_cap;
    id.delete();
    <b>let</b> ika_package_id = ika_upgrade_cap.package();
    <b>let</b> ika_system_package_id = ika_system_upgrade_cap.package();
    <b>assert</b>!(
        type_name::get&lt;IKA&gt;().get_address() == ika_package_id.to_address().to_ascii_string(),
        <a href="../ika_system/init.md#(ika_system=0x0)_init_EInvalidUpgradeCap">EInvalidUpgradeCap</a>,
    );
    <b>assert</b>!(
        type_name::get&lt;<a href="../ika_system/init.md#(ika_system=0x0)_init_InitCap">InitCap</a>&gt;().get_address() == ika_system_package_id.to_address().to_ascii_string(),
        <a href="../ika_system/init.md#(ika_system=0x0)_init_EInvalidUpgradeCap">EInvalidUpgradeCap</a>,
    );
    <b>let</b> upgrade_caps = vector[ika_upgrade_cap, ika_system_upgrade_cap];
    <b>let</b> validators = <a href="../ika_system/validator_set.md#(ika_system=0x0)_validator_set_new">validator_set::new</a>(
        min_validator_count,
        max_validator_count,
        min_validator_joining_stake,
        max_validator_count,
        reward_slashing_rate,
        ctx,
    );
    <b>let</b> <a href="../ika_system/protocol_treasury.md#(ika_system=0x0)_protocol_treasury">protocol_treasury</a> = <a href="../ika_system/protocol_treasury.md#(ika_system=0x0)_protocol_treasury_create">protocol_treasury::create</a>(
        protocol_treasury_cap,
        stake_subsidy_rate,
        stake_subsidy_period_length,
        ctx,
    );
    <b>let</b> <a href="../ika_system/protocol_cap.md#(ika_system=0x0)_protocol_cap">protocol_cap</a> = <a href="../ika_system/system.md#(ika_system=0x0)_system_create">system::create</a>(
        ika_system_package_id,
        upgrade_caps,
        validators,
        protocol_version,
        chain_start_timestamp_ms,
        epoch_duration_ms,
        stake_subsidy_start_epoch,
        <a href="../ika_system/protocol_treasury.md#(ika_system=0x0)_protocol_treasury">protocol_treasury</a>,
        ctx,
    );
    <a href="../ika_system/display.md#(ika_system=0x0)_display_create">display::create</a>(
        publisher,
        staked_ika_image_url,
        ctx,
    );
    <a href="../ika_system/protocol_cap.md#(ika_system=0x0)_protocol_cap">protocol_cap</a>
}
</code></pre>



</details>
