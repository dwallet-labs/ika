use class_groups::CiphertextSpaceGroupElement;
use dwallet_mpc_types::dwallet_mpc::VersionedDwalletDKGSecondRoundPublicOutput;

type AsyncProtocol = twopc_mpc::secp256k1::class_groups::ECDSAProtocol;

pub type DKGDecentralizedOutput =
    <AsyncProtocol as twopc_mpc::dkg::Protocol>::DecentralizedPartyDKGOutput;
use twopc_mpc::secp256k1::class_groups::{
    FUNDAMENTAL_DISCRIMINANT_LIMBS, NON_FUNDAMENTAL_DISCRIMINANT_LIMBS,
};

pub fn main() {
    let encoded = "AeoEIQK5x7wDvF6ReuA1IojfJvuWCmO3EYe23sdOZQOXzcU47iEDg3aD4D5opfGrgph8euuzq9hhSQ4pmmhxVmsSdWbwaDWAAgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAoESDjihUD9JtJjFvahzwy7FB81b5PWX5sWbxoHVHGedg4JsoBm9pH93QJFezblddf3///////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdxePvqIgRE0GNTav/mAK2ngz+WzQQzIrTJaizRDSnndIEtcXFaxJgXzeLoUQEHomxMVLnmbHC0AUXfAAfT3gpP////////////////////////////////////////////////////////////////////////////////////8hAyQJsvA7uhFbRPtiffApMziPblRgSOifM+MWWXNBkdoJ";
    let bytes = base64::decode(encoded).unwrap();
    let dkg_output: VersionedDwalletDKGSecondRoundPublicOutput =
        bcs::from_bytes(&bytes).expect("damn");
    let dkg_output = match dkg_output {
        VersionedDwalletDKGSecondRoundPublicOutput::V1(_) => panic!("nope"),
        VersionedDwalletDKGSecondRoundPublicOutput::V2(output) => output,
    };
    let dkg_output: twopc_mpc::dkg::decentralized_party::Output<
        group::secp256k1::group_element::Value,
        group::Value<CiphertextSpaceGroupElement<NON_FUNDAMENTAL_DISCRIMINANT_LIMBS>>,
    > = bcs::from_bytes(&dkg_output).expect("damn");
}
