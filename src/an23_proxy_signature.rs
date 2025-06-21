use ark_ec::CurveGroup;
use ark_ff::{
    BigInteger, Field, PrimeField, UniformRand,
    field_hashers::{DefaultFieldHasher, HashToField},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s256, Digest};
use rand::Rng;
use crate::{Error, ProxySignature};

pub struct AN23ProxySignature<G: CurveGroup> {
    _marker: std::marker::PhantomData<G>,
}

impl<G: CurveGroup> ProxySignature for AN23ProxySignature<G>
where
    G::ScalarField: PrimeField,
    G::BaseField: PrimeField,
{
    type Parameters = Parameters<G>;
    type SigningKey = SigningKey<G>;
    type VerificationKey = VerificationKey<G>;
    type Message = G::ScalarField;
    type Policy = Policy;
    type DelegationSpec = DelegationSpec;
    type DelegationInfo = Vec<SigningToken<G>>;
    type RevocationKey = Vec<G::ScalarField>;
    type RevocationState = Vec<G::ScalarField>;
    type Signature = Signature<G>;

    fn setup<R: rand::Rng>(_rng: &mut R) -> Result<Self::Parameters, crate::Error> {
        let generator = G::generator();
        Ok(Parameters { generator })
    }

    fn keygen<R: rand::Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), crate::Error> {
        let signing_key = G::ScalarField::rand(rng);
        let verification_key = parameters.generator.mul(signing_key).into();

        Ok((SigningKey(signing_key), verification_key))
    }

    fn sign<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        sk: &Self::SigningKey,
        message: &Self::Message,
        _policy: Option<&Self::Policy>,
    ) -> Result<Self::Signature, crate::Error> {
        let vk = parameters.generator.mul(sk.0).into();
        let signing_token = Self::generate_delegation_token(rng, parameters, sk, &vk)?;

        Self::delegated_sign(rng, parameters, &mut vec![signing_token], message)
    }

    fn delegate<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        sk: &Self::SigningKey,
        deg_spec: &Self::DelegationSpec,
    ) -> Result<(Self::DelegationInfo, Self::RevocationKey), crate::Error> {
        let vk = parameters.generator.mul(sk.0).into();

        let mut delegation_info = Vec::new();
        let mut rev_key = Vec::new();

        for _ in 0..deg_spec.number_of_tokens {
            let signing_token = Self::generate_delegation_token(rng, parameters, sk, &vk)?;
            rev_key.push(signing_token.m0); // Store m0 as revocation key
            delegation_info.push(signing_token);
        }

        Ok((delegation_info, rev_key))
    }

    fn delegated_sign<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        delegation_info: &mut Self::DelegationInfo,
        message: &Self::Message,
    ) -> Result<Self::Signature, crate::Error> {
        let signing_token = delegation_info.pop().ok_or(Error::NoDelegationToken)?;

        // Second layer, uses z0 as signing key, signs real message m1;
        let Z0 = parameters.generator.mul(signing_token.z0);
        let r1 = G::ScalarField::rand(rng); // e
        let R1 = parameters.generator.mul(r1);
        let c1 = hash::<G>(vec![
            Message::Field(message.clone()),
            Message::Curve(Z0.into()),
            Message::Curve(R1.into()),
        ]); // c
        let z1 = r1 + c1 * signing_token.z0; // s

        let sigma = Sigma {
            c0: signing_token.c0,
            c1,
            z1,
        };
        let theta = Theta {
            m0: signing_token.m0,
            Z0,
        };

        Ok(Signature { sigma, theta })
    }

    fn revoke(
        _parameters: &Self::Parameters,
        _delegation_info: &Self::DelegationInfo,
        rev_key: &Self::RevocationKey,
        rev_state: &mut Self::RevocationState,
    ) -> Result<(), crate::Error> {
        rev_state.extend(rev_key.iter().cloned());
        Ok(())
    }

    fn verify(
        parameters: &Self::Parameters,
        vk: &Self::VerificationKey,
        message: &Self::Message,
        signature: &Self::Signature,
        rev_state: &mut Self::RevocationState,
    ) -> Result<bool, crate::Error> {
        for &nonce in rev_state.iter() {
            if signature.theta.m0 == nonce {
                return Err(Error::UseOfRevokedToken); // Token is revoked
            }
        }

        //       R0 = Z0 + [-c0]X
        // => [r0]G = [z0]G - [c0 * x] G
        // =>    z0 = r0 + c0 * x
        let R0 = signature.theta.Z0 + vk.clone() * -signature.sigma.c0; // R
        //       R1 = [z1]G + [-c1]Z0
        // => [r1]G = [z1]G + [-c1 * z0]G
        // =>    z1 = r1 + c1 * z0
        let R1 = parameters.generator.mul(signature.sigma.z1)
            + signature.theta.Z0.mul(-signature.sigma.c1); // E

        if signature.sigma.c0
            != hash::<G>(vec![
                Message::Field(signature.theta.m0),
                Message::Curve(vk.clone()), // [x]G
                Message::Curve(R0.into()),  // [r0]G
            ])
        {
            return Ok(false);
        }

        if signature.sigma.c1
            != hash::<G>(vec![
                Message::Field(message.clone()),
                Message::Curve(signature.theta.Z0.into()),
                Message::Curve(R1.into()),
            ])
        {
            return Ok(false);
        }

        rev_state.push(signature.theta.m0);

        Ok(true)
    }
}

impl<G: CurveGroup> AN23ProxySignature<G>
where
    G::ScalarField: PrimeField,
    G::BaseField: PrimeField,
{
    fn generate_delegation_token<R: Rng>(
        rng: &mut R,
        parameters: &Parameters<G>,
        sk: &SigningKey<G>,
        vk: &VerificationKey<G>,
    ) -> Result<SigningToken<G>, crate::Error> {
        let m0 = G::ScalarField::rand(rng); // k
        let r0 = G::ScalarField::rand(rng); // r
        let R0 = parameters.generator.mul(r0);
        let c0 = hash::<G>(vec![
            Message::Field(m0),
            Message::Curve(vk.clone()), // [x]G
            Message::Curve(R0.into()),
        ]); // w
        let z0 = r0 + c0 * sk.0; // z

        Ok(SigningToken { z0, c0, m0 })
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<G: CurveGroup> {
    pub generator: G,
}

#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigningKey<G: CurveGroup>(pub G::ScalarField);

pub type VerificationKey<G> = <G as CurveGroup>::Affine;

pub struct Policy {
    pub amount: u64, // The amount of delegation allowed
}

pub struct DelegationSpec {
    pub number_of_tokens: u64,
}

/// A token produced by the original signer and user by the proxy to produce a signature.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SigningToken<G: CurveGroup> {
    z0: G::ScalarField, // z
    c0: G::ScalarField, // w
    m0: G::ScalarField, // k
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
/// A AN23 signature. Can be produced by either the original signer or the proxy.
pub struct Signature<G: CurveGroup> {
    pub sigma: Sigma<G::ScalarField>,
    pub theta: Theta<G>,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Sigma<F: Field> {
    pub c0: F,
    pub c1: F,
    pub z1: F,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Theta<G: CurveGroup> {
    pub m0: G::ScalarField,
    pub Z0: G,
}

enum Message<G: CurveGroup> {
    Field(G::ScalarField),
    Curve(G::Affine),
    Bytes(Vec<u8>),
}

impl<G: CurveGroup> Message<G> {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Field(value) => value.into_bigint().to_bytes_be(),
            Self::Curve(point) => {
                let mut uncompressed_bytes = Vec::new();
                point
                    .serialize_uncompressed(&mut uncompressed_bytes)
                    .unwrap();

                uncompressed_bytes
            }
            Self::Bytes(bytes) => bytes.clone(),
        }
    }
}

fn hash_to_field<F: PrimeField>(data: &[u8]) -> F {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let mut out = hasher.finalize();
    out[31] = 0;
    let out = F::from_le_bytes_mod_order(&out);
    out
}
fn hash<G: CurveGroup>(message: Vec<Message<G>>) -> G::ScalarField
where
    G::ScalarField: PrimeField,
    G::BaseField: PrimeField,
{
    let preimage = message
        .iter()
        .flat_map(|m| m.to_bytes())
        .collect::<Vec<_>>();
    hash_to_field(&preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noir_utils::{
        grumpkin_fr_to_nr_code, grumpkin_point_to_nr_code, grumpkin_sig_to_nr_code,
    };
    use ark_grumpkin::{Fr, Projective};

    #[test]
    fn test_an23_proxy_signature_vanilla() {
        use ark_std::test_rng;
        let mut rng = test_rng();
        let parameters = AN23ProxySignature::<Projective>::setup(&mut rng).unwrap();
        let (sk, vk) = AN23ProxySignature::<Projective>::keygen(&mut rng, &parameters).unwrap();

        let message = Fr::rand(&mut rng);

        let signature =
            AN23ProxySignature::<Projective>::sign(&mut rng, &parameters, &sk, &message, None)
                .unwrap();

        let verifier_decision = AN23ProxySignature::<Projective>::verify(
            &parameters,
            &vk,
            &message,
            &signature,
            &mut vec![],
        )
        .unwrap();

        assert!(verifier_decision);
    }

    #[test]
    fn test_an23_proxy_signature_with_delegation() {
        use ark_std::test_rng;
        let mut rng = test_rng();
        let parameters = AN23ProxySignature::<Projective>::setup(&mut rng).unwrap();
        let (sk, vk) = AN23ProxySignature::<Projective>::keygen(&mut rng, &parameters).unwrap();

        let (mut delegation_info, _) = AN23ProxySignature::<Projective>::delegate(
            &mut rng,
            &parameters,
            &sk,
            &DelegationSpec {
                number_of_tokens: 5,
            },
        )
        .unwrap();

        let message = Fr::rand(&mut rng);

        let signature = AN23ProxySignature::<Projective>::delegated_sign(
            &mut rng,
            &parameters,
            &mut delegation_info,
            &message,
        )
        .unwrap();

        let verifier_decision = AN23ProxySignature::<Projective>::verify(
            &parameters,
            &vk,
            &message,
            &signature,
            &mut vec![],
        )
        .unwrap();

        assert!(verifier_decision);
    }

    #[test]
    fn test_verifier_revocation() {
        use ark_std::test_rng;
        let mut rng = test_rng();
        let parameters = AN23ProxySignature::<Projective>::setup(&mut rng).unwrap();
        let (sk, vk) = AN23ProxySignature::<Projective>::keygen(&mut rng, &parameters).unwrap();

        let mut rev_state = Vec::new(); // Initialize an empty revocation state

        let (mut delegation_info, _) = AN23ProxySignature::<Projective>::delegate(
            &mut rng,
            &parameters,
            &sk,
            &DelegationSpec {
                number_of_tokens: 5,
            },
        )
        .unwrap();

        let message = Fr::rand(&mut rng);

        let signature = AN23ProxySignature::<Projective>::delegated_sign(
            &mut rng,
            &parameters,
            &mut delegation_info,
            &message,
        )
        .unwrap();

        // Verify the signature once and change revocation state
        let verifier_decision = AN23ProxySignature::<Projective>::verify(
            &parameters,
            &vk,
            &message,
            &signature,
            &mut rev_state,
        )
        .unwrap();

        assert!(verifier_decision); // Initial verification should succeed

        assert!(rev_state.len() == 1); // Ensure revocation state has one entry

        // Now, try to verify the same signature again, which should fail due to revocation
        let second_verifier_decision = AN23ProxySignature::<Projective>::verify(
            &parameters,
            &vk,
            &message,
            &signature,
            &mut rev_state,
        );
        assert_eq!(second_verifier_decision, Err(Error::UseOfRevokedToken)); // Should fail due to revocation
    }

    #[test]
    fn test_issuer_revocation() {
        use ark_std::test_rng;
        let mut rng = test_rng();
        let parameters = AN23ProxySignature::<Projective>::setup(&mut rng).unwrap();
        let (sk, vk) = AN23ProxySignature::<Projective>::keygen(&mut rng, &parameters).unwrap();

        let mut rev_state = Vec::new(); // Initialize an empty revocation state

        let (mut delegation_info, rev_key) = AN23ProxySignature::<Projective>::delegate(
            &mut rng,
            &parameters,
            &sk,
            &DelegationSpec {
                number_of_tokens: 5,
            },
        )
        .unwrap();

        let message = Fr::rand(&mut rng);

        // Revoke the delegation
        AN23ProxySignature::<Projective>::revoke(
            &parameters,
            &delegation_info,
            &rev_key,
            &mut rev_state,
        )
        .unwrap();

        // Sign after revocation
        let signature = AN23ProxySignature::<Projective>::delegated_sign(
            &mut rng,
            &parameters,
            &mut delegation_info,
            &message,
        )
        .unwrap();

        let verifier_decision = AN23ProxySignature::<Projective>::verify(
            &parameters,
            &vk,
            &message,
            &signature,
            &mut rev_state,
        );

        assert_eq!(verifier_decision, Err(Error::UseOfRevokedToken)); // Should fail due to revocation
    }

    #[test]
    fn test_grumpkin() {
        let mut rng = thread_rng();

        let m = Fr::rand(&mut rng);

        let parameters = AN23ProxySignature::<Projective>::setup(&mut rng).unwrap();
        let (sk, vk) = AN23ProxySignature::<Projective>::keygen(&mut rng, &parameters).unwrap();

        let signature =
            AN23ProxySignature::<Projective>::sign(&mut rng, &parameters, &sk, &m, None).unwrap();

        println!("    let vk = {};", grumpkin_point_to_nr_code(vk.into()));
        println!("    let msg = {};", grumpkin_fr_to_nr_code(m));
        println!("{}", grumpkin_sig_to_nr_code(&signature));

        let verifier_decision =
            AN23ProxySignature::<Projective>::verify(&parameters, &vk, &m, &signature, &mut vec![])
                .unwrap();

        assert!(verifier_decision);
    }
}
