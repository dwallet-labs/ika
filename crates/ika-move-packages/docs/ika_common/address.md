---
title: Module `ika_common::address`
---



-  [Function `ed25519_address`](#ika_common_address_ed25519_address)


<pre><code><b>use</b> <a href="../std/ascii.md#std_ascii">std::ascii</a>;
<b>use</b> <a href="../std/bcs.md#std_bcs">std::bcs</a>;
<b>use</b> <a href="../std/option.md#std_option">std::option</a>;
<b>use</b> <a href="../std/string.md#std_string">std::string</a>;
<b>use</b> <a href="../std/vector.md#std_vector">std::vector</a>;
<b>use</b> <a href="../sui/address.md#sui_address">sui::address</a>;
<b>use</b> <a href="../sui/hash.md#sui_hash">sui::hash</a>;
<b>use</b> <a href="../sui/hex.md#sui_hex">sui::hex</a>;
</code></pre>



<a name="ika_common_address_ed25519_address"></a>

## Function `ed25519_address`



<pre><code><b>public</b> <b>fun</b> <a href="../ika_common/address.md#ika_common_address_ed25519_address">ed25519_address</a>(public_key: vector&lt;u8&gt;): <b>address</b>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="../ika_common/address.md#ika_common_address_ed25519_address">ed25519_address</a>(public_key: vector&lt;u8&gt;): <b>address</b> {
    <b>let</b> <b>mut</b> hasher = vector[0u8];
    hasher.append(public_key);
    <b>let</b> address_bytes = hash::blake2b256(&hasher);
    address::from_bytes(address_bytes)
}
</code></pre>



</details>
