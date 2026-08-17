/// Discovery index for the recovery package.
///
/// The `Registry` is a single shared object created once at publish time. It
/// maps a member's canonical id bytes to the set of recovery objects that
/// member belongs to. Member id bytes match `auth::new_member_id_bytes`:
/// 33 bytes for a passkey (compressed secp256r1 public key) and 32 bytes for
/// an address — different lengths so the two namespaces never collide.
///
/// `register` / `unregister` are `public(package)` and only called from
/// `recovery::recovery` (on `create`, `execute_enrollment`). The reader
/// `list_for_member` is `public` so any client can discover the recoveries
/// they belong to without already knowing the recovery id.
module recovery::registry;

use sui::table::{Self, Table};
use sui::vec_set::{Self, VecSet};

/// One-time witness, consumed by `init` to ensure exactly one Registry is
/// created at publish time.
public struct REGISTRY has drop {}

public struct Registry has key {
    id: UID,
    by_member: Table<vector<u8>, VecSet<ID>>,
}

fun init(_otw: REGISTRY, ctx: &mut TxContext) {
    transfer::share_object(Registry {
        id: object::new(ctx),
        by_member: table::new(ctx),
    });
}

public(package) fun register(
    self: &mut Registry,
    member_id: vector<u8>,
    recovery_id: ID,
) {
    if (!self.by_member.contains(member_id)) {
        self.by_member.add(member_id, vec_set::empty<ID>());
    };
    let set = self.by_member.borrow_mut(member_id);
    if (!set.contains(&recovery_id)) set.insert(recovery_id);
}

public(package) fun unregister(
    self: &mut Registry,
    member_id: vector<u8>,
    recovery_id: ID,
) {
    if (!self.by_member.contains(member_id)) return;
    let set = self.by_member.borrow_mut(member_id);
    if (set.contains(&recovery_id)) set.remove(&recovery_id);
}

public fun list_for_member(self: &Registry, member_id: vector<u8>): vector<ID> {
    if (!self.by_member.contains(member_id)) return vector[];
    *self.by_member.borrow(member_id).keys()
}
