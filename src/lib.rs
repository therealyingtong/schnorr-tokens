use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{
    BigInteger, Field, PrimeField, UniformRand,
    field_hashers::{DefaultFieldHasher, HashToField},
};
use ark_std::rand::thread_rng;
use blake2::{Blake2s256, Digest};
use sha2::Sha256;

struct Key<G: CurveGroup> {
    x: G::ScalarField,
    X: G, // [x]G
}

struct SigningToken<G: CurveGroup> {
    z0: G::ScalarField, // z
    c0: G::ScalarField, // w
    m0: G::ScalarField, // k
}

struct Signature<G: CurveGroup> {
    sigma: Sigma<G::ScalarField>,
    theta: Theta<G>,
}

struct Sigma<F: Field> {
    c0: F,
    c1: F,
    z1: F,
}

struct Theta<G: CurveGroup> {
    m0: G::ScalarField,
    Z0: G,
}

enum Message<G: CurveGroup> {
    Field(G::ScalarField),
    Curve(G),
}

impl<G: CurveGroup> Message<G>
where
    G::BaseField: PrimeField,
{
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Field(value) => value.into_bigint().to_bytes_le(),
            Self::Curve(point) => {
                let mut x = point.into_affine().x().unwrap().into_bigint().to_bytes_le();
                let mut y = point.into_affine().y().unwrap().into_bigint().to_bytes_le();
                x.append(&mut y);
                x
            }
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

impl<G: CurveGroup> Key<G>
where
    G::BaseField: PrimeField,
{
    fn new() -> Self {
        let mut rng = thread_rng();
        let x = G::ScalarField::rand(&mut rng);
        let X = G::generator().mul(x);
        Key { x, X }
    }

    fn gen_token(&self) -> SigningToken<G> {
        let mut rng = thread_rng();
        let m0 = G::ScalarField::rand(&mut rng); // k
        let r0 = G::ScalarField::rand(&mut rng); // r
        let R0 = G::generator().mul(r0);
        let c0 = hash(vec![
            Message::Field(m0),
            Message::Curve(self.X),
            Message::Curve(R0),
        ]); // w
        let z0 = r0 + c0 * self.x; // z

        SigningToken { z0, c0, m0 }
    }

    fn sign(&self, m: G::ScalarField) -> Signature<G> {
        let signing_token = self.gen_token();
        signing_token.deg_sign(m)
    }

    // fn delegate(&self, bulletin_board: String) -> SigningToken<G> {
    //     let signing_token = self.gen_token();
    //     bulletin_board.delegate(signing_token.m0); // k

    //     signing_token
    // }
}

impl<G: CurveGroup> SigningToken<G>
where
    G::BaseField: PrimeField,
{
    fn deg_sign(&self, m: G::ScalarField) -> Signature<G> {
        let mut rng = thread_rng();

        // Second layer, uses z0 as signing key, signs real message m1;
        let Z0 = G::generator().mul(self.z0);
        let m1 = m;
        let r1 = G::ScalarField::rand(&mut rng); // e
        let R1 = G::generator().mul(r1);
        let c1 = hash(vec![
            Message::Field(m1),
            Message::Curve(Z0),
            Message::Curve(R1),
        ]); // c
        let z1 = r1 + c1 * self.z0; // s

        let sigma = Sigma {
            c0: self.c0,
            c1,
            z1,
        };
        let theta = Theta { m0: self.m0, Z0 };

        Signature { sigma, theta }
    }

    // fn revoke(&self, bulletin_board: String) {
    //     bulletin_board.revoke(self.m0);
    // }
}

impl<G: CurveGroup> Signature<G>
where
    G::BaseField: PrimeField,
{
    fn verify(&self, m: G::ScalarField, vk: G, _bulletin_board: String) -> bool {
        //       R0 = Z0 + [-c0]X
        // => [r0]G = [z0]G - [c0 * x] G
        // =>    z0 = r0 + c0 * x
        let R0 = self.theta.Z0 + vk.mul(-self.sigma.c0); // R
        //       R1 = [z1]G + [-c1]Z0
        // => [r1]G = [z1]G + [-c1 * z0]G
        // =>    z1 = r1 + c1 * z0
        let R1 = G::generator().mul(self.sigma.z1) + self.theta.Z0.mul(-self.sigma.c1); // E

        assert_eq!(
            self.sigma.c0,
            hash(vec![
                Message::Field(self.theta.m0),
                Message::Curve(vk), // [x]G
                Message::Curve(R0)  // [r0]G
            ])
        );
        assert_eq!(
            self.sigma.c1,
            hash(vec![
                Message::Field(m),
                Message::Curve(self.theta.Z0),
                Message::Curve(R1)
            ])
        );

        true
    }
}

#[test]
fn test_random() {
    let mut rng = thread_rng();

    use ark_bn254::{Fr, G1Projective};
    let key = Key::<G1Projective>::new();
    let m = Fr::rand(&mut rng);

    let token = key.gen_token();

    let signature = key.sign(m);
    assert!(signature.verify(m, key.X, "".to_string()));

    let delegated_signature = token.deg_sign(m);
    assert!(delegated_signature.verify(m, key.X, "".to_string()));
}

fn grumpkin_fr_to_nr_code(fr: ark_grumpkin::Fr) -> String {
    let bi = fr.into_bigint().0;
    let lo: u128 = (bi[0] as u128) | (bi[1] as u128) << 64;
    let hi: u128 = (bi[2] as u128) | (bi[3] as u128) << 64;
    format!("EmbeddedCurveScalar::new(0x{:x}, 0x{:x})", lo, hi)
}

fn grumpkin_point_to_nr_code(point: ark_grumpkin::Projective) -> String {
    let aff = point.into_affine();
    format!(
        "EmbeddedCurvePoint {{x: {}, y: {}, is_infinite: false}}",
        aff.x().unwrap(),
        aff.y().unwrap()
    )
    .to_string()
}

fn grumpkin_sig_to_nr_code(signature: &Signature<ark_grumpkin::Projective>) -> String {
    let mut s = String::new();
    s.push_str("    let sigma = Sigma {\n");
    s.push_str(&format!(
        "        c0: {},\n",
        grumpkin_fr_to_nr_code(signature.sigma.c0)
    ));
    s.push_str(&format!(
        "        c1: {},\n",
        grumpkin_fr_to_nr_code(signature.sigma.c1)
    ));
    s.push_str(&format!(
        "        z1: {}\n",
        grumpkin_fr_to_nr_code(signature.sigma.z1)
    ));
    s.push_str("    };\n");
    s.push_str("    let theta = Theta {\n");
    s.push_str(&format!(
        "        m0: {},\n",
        grumpkin_fr_to_nr_code(signature.theta.m0)
    ));
    s.push_str(&format!(
        "        Z0: {}\n",
        grumpkin_point_to_nr_code(signature.theta.Z0)
    ));
    s.push_str("    };\n");
    s.push_str("    let sig = Signature { sigma, theta };\n");
    s
}

#[test]
fn test_grumpkin() {
    use ark_grumpkin::{Fr, Projective};
    let mut rng = thread_rng();
    let m = Fr::rand(&mut rng);
    let key = Key::<Projective>::new();
    let signature = key.sign(m);

    println!("    let vk = {};", grumpkin_point_to_nr_code(key.X));
    println!("    let msg = {};", grumpkin_fr_to_nr_code(m));
    println!("{}", grumpkin_sig_to_nr_code(&signature));

    assert!(signature.verify(m, key.X, "".to_string()));
}
