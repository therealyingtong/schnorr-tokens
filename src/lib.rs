use ark_ec::CurveGroup;
use ark_ff::{
    BigInteger, Field, PrimeField, UniformRand,
    field_hashers::{DefaultFieldHasher, HashToField},
};
use ark_std::rand::thread_rng;
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
        }
    }
}

fn hash<G: CurveGroup>(message: Vec<Message<G>>) -> G::ScalarField {
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<G::ScalarField>>::new(&[]);
    let preimage = message
        .iter()
        .map(|m| m.to_bytes())
        .flatten()
        .collect::<Vec<_>>();
    let hashes: [G::ScalarField; 1] = hasher.hash_to_field(&preimage);
    hashes[0]
}

impl<G: CurveGroup> Key<G> {
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

impl<G: CurveGroup> SigningToken<G> {
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

impl<G: CurveGroup> Signature<G> {
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
                Message::Curve(R0) // [r0]G
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
