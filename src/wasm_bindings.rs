use crate::ProxySignature;
use crate::an23_proxy_signature::{AN23ProxySignature, DelegationSpec, Parameters, SigningKey};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Fq;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
#[derive(Clone)]
pub struct Fr {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl Fr {
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl From<ark_grumpkin::Fr> for Fr {
    fn from(value: ark_grumpkin::Fr) -> Self {
        Fr {
            bytes: value.into_bigint().to_bytes_le(),
        }
    }
}

impl From<&Fr> for ark_grumpkin::Fr {
    fn from(value: &Fr) -> Self {
        let bytes = value.clone().bytes;
        ark_grumpkin::Fr::from_le_bytes_mod_order(&bytes)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct CurvePoint {
    x: Vec<u8>,
    y: Vec<u8>,
}

#[wasm_bindgen]
impl CurvePoint {
    pub fn x(&self) -> Vec<u8> {
        self.x.clone()
    }

    pub fn y(&self) -> Vec<u8> {
        self.y.clone()
    }
}

impl From<ark_grumpkin::Projective> for CurvePoint {
    fn from(value: ark_grumpkin::Projective) -> Self {
        let aff = value.into_affine();
        aff.into()
    }
}

impl From<ark_grumpkin::Affine> for CurvePoint {
    fn from(value: ark_grumpkin::Affine) -> Self {
        let x = value.x().unwrap().into_bigint().to_bytes_le();
        let y = value.y().unwrap().into_bigint().to_bytes_le();
        CurvePoint { x, y }
    }
}

impl From<&CurvePoint> for ark_grumpkin::Projective {
    fn from(value: &CurvePoint) -> Self {
        let x = Fq::from_le_bytes_mod_order(&value.x);
        let y = Fq::from_le_bytes_mod_order(&value.y);
        ark_grumpkin::Affine::new(x, y).into()
    }
}

#[wasm_bindgen]
pub fn setup() -> CurvePoint {
    let mut rng = OsRng;
    AN23ProxySignature::<ark_grumpkin::Projective>::setup(&mut rng)
        .unwrap()
        .generator
        .into()
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Keypair {
    sk: Fr,
    vk: CurvePoint,
}

#[wasm_bindgen]
impl Keypair {
    pub fn sk(&self) -> Fr {
        self.sk.clone()
    }

    pub fn vk(&self) -> CurvePoint {
        self.vk.clone()
    }
}

#[wasm_bindgen]
pub fn keygen(params: &CurvePoint) -> Keypair {
    let mut rng = OsRng;
    let params: ark_grumpkin::Projective = params.into();
    let (sk, vk) = AN23ProxySignature::<ark_grumpkin::Projective>::keygen(
        &mut rng,
        &Parameters { generator: params },
    )
    .unwrap();
    Keypair {
        sk: sk.0.into(),
        vk: vk.into(),
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Signature {
    sigma_c0: Fr,
    sigma_c1: Fr,
    sigma_z1: Fr,
    theta_m0: Fr,
    theta_z0: CurvePoint,
}

#[wasm_bindgen]
impl Signature {
    pub fn sigma_c0(&self) -> Fr {
        self.sigma_c0.clone()
    }

    pub fn sigma_c1(&self) -> Fr {
        self.sigma_c1.clone()
    }

    pub fn sigma_z1(&self) -> Fr {
        self.sigma_z1.clone()
    }

    pub fn theta_m0(&self) -> Fr {
        self.theta_m0.clone()
    }

    pub fn theta_z0(&self) -> CurvePoint {
        self.theta_z0.clone()
    }
}

impl From<crate::an23_proxy_signature::Signature<ark_grumpkin::Projective>> for Signature {
    fn from(sig: crate::an23_proxy_signature::Signature<ark_grumpkin::Projective>) -> Self {
        Signature {
            sigma_c0: sig.sigma.c0.into(),
            sigma_c1: sig.sigma.c1.into(),
            sigma_z1: sig.sigma.z1.into(),
            theta_m0: sig.theta.m0.into(),
            theta_z0: sig.theta.Z0.into(),
        }
    }
}

#[wasm_bindgen]
pub fn sign(params: &CurvePoint, sk: &Fr, message: &Fr, policy: Option<u64>) -> Signature {
    let params = Parameters {
        generator: params.into(),
    };
    let sk = SigningKey::<ark_grumpkin::Projective>(sk.into());
    let message = ark_grumpkin::Fr::from(message);
    let policy = policy.map(|p| crate::an23_proxy_signature::Policy { amount: p });
    AN23ProxySignature::<ark_grumpkin::Projective>::sign(
        &mut OsRng,
        &params,
        &sk,
        &message,
        policy.as_ref(),
    )
    .unwrap()
    .into()
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct SigningToken {
    z0: Fr,
    c0: Fr,
    m0: Fr,
}

#[wasm_bindgen]
impl SigningToken {
    pub fn z0(&self) -> Fr {
        self.z0.clone()
    }

    pub fn c0(&self) -> Fr {
        self.c0.clone()
    }

    pub fn m0(&self) -> Fr {
        self.m0.clone()
    }
}

impl From<crate::an23_proxy_signature::SigningToken<ark_grumpkin::Projective>> for SigningToken {
    fn from(token: crate::an23_proxy_signature::SigningToken<ark_grumpkin::Projective>) -> Self {
        SigningToken {
            z0: token.z0.into(),
            c0: token.c0.into(),
            m0: token.m0.into(),
        }
    }
}

impl From<&SigningToken> for crate::an23_proxy_signature::SigningToken<ark_grumpkin::Projective> {
    fn from(token: &SigningToken) -> Self {
        crate::an23_proxy_signature::SigningToken {
            z0: ark_grumpkin::Fr::from(&token.z0),
            c0: ark_grumpkin::Fr::from(&token.c0),
            m0: ark_grumpkin::Fr::from(&token.m0),
        }
    }
}

#[wasm_bindgen]
pub struct DelegationRes {
    delegation_info: Vec<SigningToken>,
    revokation_key: Vec<Fr>,
}

#[wasm_bindgen]
impl DelegationRes {
    pub fn delegation_info(&self) -> Vec<SigningToken> {
        self.delegation_info.clone()
    }

    pub fn revokation_key(&self) -> Vec<Fr> {
        self.revokation_key.clone()
    }
}

#[wasm_bindgen]
pub fn delegate(params: &CurvePoint, sk: &Fr, delegation_spec: u64) -> DelegationRes {
    let params = Parameters {
        generator: params.into(),
    };
    let sk = SigningKey::<ark_grumpkin::Projective>(sk.into());
    let deg_spec = DelegationSpec {
        number_of_tokens: delegation_spec,
    };

    let (delegation_info, rev_key) = AN23ProxySignature::<ark_grumpkin::Projective>::delegate(
        &mut OsRng, &params, &sk, &deg_spec,
    )
    .unwrap();

    DelegationRes {
        delegation_info: delegation_info.into_iter().map(Into::into).collect(),
        revokation_key: rev_key.into_iter().map(Into::into).collect(),
    }
}

#[wasm_bindgen]
pub fn delegated_sign(
    params: &CurvePoint,
    delegation_info: Vec<SigningToken>,
    message: &Fr,
) -> Signature {
    let params = Parameters {
        generator: params.into(),
    };
    let mut delegation_info: Vec<
        crate::an23_proxy_signature::SigningToken<ark_grumpkin::Projective>,
    > = delegation_info.iter().map(Into::into).collect();
    let message = ark_grumpkin::Fr::from(message);

    AN23ProxySignature::<ark_grumpkin::Projective>::delegated_sign(
        &mut OsRng,
        &params,
        &mut delegation_info,
        &message,
    )
    .unwrap()
    .into()
}

#[wasm_bindgen]
pub fn hash_to_field(message: &[u8]) -> Fr {
    crate::an23_proxy_signature::hash_to_field::<ark_grumpkin::Fr>(message).into()
}
