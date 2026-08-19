// Move-side domain-separation tags. WebAuthn challenges include one of these
// so a passkey signature authorising one Move action cannot be replayed for
// another. Solana SDK has its own parallel set with different prefixes.

export const TAG_PROPOSE = 'recovery::propose';
export const TAG_APPROVE = 'recovery::approve';
export const TAG_EXECUTE = 'recovery::execute';
export const TAG_ENROLL_PROPOSE = 'recovery::enroll_propose';
export const TAG_ENROLL_APPROVE = 'recovery::enroll_approve';
export const TAG_ROSTER_CHANGE_PROPOSE = 'recovery::roster_change_propose';
export const TAG_ROSTER_CHANGE_APPROVE = 'recovery::roster_change_approve';
