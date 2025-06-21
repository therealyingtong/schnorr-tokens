use ark_grumpkin::Projective as GrumpkinCurve;
use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;
use schnorr_tokens::ProxySignature;
use schnorr_tokens::an23_proxy_signature::{AN23ProxySignature, DelegationSpec};
use std::fs::File;
use std::io::Write;

fn main() {
    let mut rng = OsRng::default();

    let parameters = AN23ProxySignature::<GrumpkinCurve>::setup(&mut rng).expect("Setup failed");

    let (signing_key, verification_key) =
        AN23ProxySignature::keygen(&mut rng, &parameters).expect("Key generation failed");

    let delegation_spec = DelegationSpec {
        number_of_tokens: 1,
    };

    let (delegation_info, _) =
        AN23ProxySignature::delegate(&mut rng, &parameters, &signing_key, &delegation_spec)
            .expect("Delegation failed");

    // Export parameters to a file
    let mut params_bytes = Vec::new();
    parameters
        .serialize_compressed(&mut params_bytes)
        .expect("Serialization failed");
    let mut file = File::create("examples/parameters.bin").expect("Unable to create file");
    file.write_all(&params_bytes).expect("Unable to write data");

    // Export verification_key to a file
    let mut vk_bytes = Vec::new();
    verification_key
        .serialize_compressed(&mut vk_bytes)
        .expect("Serialization failed");
    let mut file = File::create("examples/verification_key.bin").expect("Unable to create file");
    file.write_all(&vk_bytes).expect("Unable to write data");

    // Export delegation_info to a file
    let mut delegation_bytes = Vec::new();
    delegation_info
        .serialize_compressed(&mut delegation_bytes)
        .expect("Serialization failed");
    let mut file = File::create("examples/delegation_info.bin").expect("Unable to create file");
    file.write_all(&delegation_bytes)
        .expect("Unable to write data");
}
