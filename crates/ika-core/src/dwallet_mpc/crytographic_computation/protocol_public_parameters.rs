#[derive(Clone, Debug, Eq, PartialEq, strum_macros::Display)]
pub enum ProtocolPublicParametersByCurve {
    #[strum(to_string = "Protocol Public Parameters - curve: Secp256k1")]
    Secp256k1(twopc_mpc::secp256k1::class_groups::ProtocolPublicParameters),
    #[strum(to_string = "Protocol Public Parameters - curve: Secp256r1")]
    Secp256r1(twopc_mpc::secp256r1::class_groups::ProtocolPublicParameters),
    #[strum(to_string = "Protocol Public Parameters - curve: Curve25519")]
    Curve25519(twopc_mpc::curve25519::class_groups::ProtocolPublicParameters),
    #[strum(to_string = "Protocol Public Parameters - curve: Ristretto")]
    Ristretto(twopc_mpc::ristretto::class_groups::ProtocolPublicParameters),
}
