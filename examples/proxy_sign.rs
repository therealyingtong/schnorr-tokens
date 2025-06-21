use ark_ff::UniformRand;
use ark_grumpkin::{Fr as GrumpkinScalar, Projective as GrumpkinCurve};
use ark_serialize::CanonicalDeserialize;
use rand::rngs::OsRng;
use schnorr_tokens::ProxySignature;
use schnorr_tokens::an23_proxy_signature::{AN23ProxySignature, DelegationSpec};
use std::fs::File;
use std::io::Read;

fn main() {
    let mut rng = OsRng;
    let mut revocation_state = Vec::new(); // Initialize an empty revocation state

    println!("Importing parameters, verification key, and delegation info...\n");
    // Import parameters
    let mut params_bytes = Vec::new();
    File::open("examples/parameters.bin")
        .expect("Unable to open parameters file. Make sure to run the delegate example first.")
        .read_to_end(&mut params_bytes)
        .expect("Unable to read parameters file");
    let parameters =
        <AN23ProxySignature<GrumpkinCurve> as ProxySignature>::Parameters::deserialize_compressed(
            &*params_bytes,
        )
        .expect("Deserialization failed");

    // Import verification key
    let mut vk_bytes = Vec::new();
    File::open("examples/verification_key.bin")
        .expect("Unable to open verification key file")
        .read_to_end(&mut vk_bytes)
        .expect("Unable to read verification key file");
    let verification_key = <AN23ProxySignature<GrumpkinCurve> as ProxySignature>::VerificationKey::deserialize_compressed(&*vk_bytes)
        .expect("Deserialization failed");

    // Import delegation info
    let mut delegation_bytes = Vec::new();
    File::open("examples/delegation_info.bin")
        .expect("Unable to open delegation info file")
        .read_to_end(&mut delegation_bytes)
        .expect("Unable to read delegation info file");
    let delegation_info = <AN23ProxySignature<GrumpkinCurve> as ProxySignature>::DelegationInfo::deserialize_compressed(&*delegation_bytes)
        .expect("Deserialization failed");

    println!("Generating a random message\n");
    // Now you can use `parameters`, `verification_key`, and `delegation_info` as needed
    let message = GrumpkinScalar::rand(&mut rng);

    println!("Signing using the delegation info\n");
    let signature = AN23ProxySignature::<GrumpkinCurve>::delegated_sign(
        &mut rng,
        &parameters,
        &mut delegation_info.clone(),
        &message,
    )
    .expect("Delegated signing failed");

    println!("{:?}\n", signature);

    let verifier_decision = AN23ProxySignature::<GrumpkinCurve>::verify(
        &parameters,
        &verification_key,
        &message,
        &signature,
        &mut revocation_state,
    )
    .expect("Verification failed");

    if verifier_decision {
        println!("Signature is valid.");
    } else {
        println!("Signature is invalid.");
    }
}
