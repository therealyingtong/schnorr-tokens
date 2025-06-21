use std::{embedded_curve_ops::{multi_scalar_mul, EmbeddedCurveScalar, EmbeddedCurvePoint}, hash::{blake2s, poseidon2_permutation}};

struct Sigma {
    c0: EmbeddedCurveScalar,
    c1: EmbeddedCurveScalar,
    z1: EmbeddedCurveScalar,
}

struct Theta {
    m0: EmbeddedCurveScalar,
    Z0: EmbeddedCurvePoint,
}

struct Signature {
    sigma: Sigma,
    theta: Theta,
}

fn hash_to_field<let N: u32>(input: [u8;N]) -> EmbeddedCurveScalar {
    let bytes = blake2s(input);
    let mut hi_bytes = [0; 16];
    let mut lo_bytes = [0; 16];
    for i in 0..16 {
        lo_bytes[i as u32] = bytes[i as u32];
        hi_bytes[i as u32] = bytes[(i + 16) as u32];
    }
    hi_bytes[15] = 0;
    let lo = Field::from_le_bytes(lo_bytes);
    let hi = Field::from_le_bytes(hi_bytes);
    let output = EmbeddedCurveScalar::new(lo, hi);
    output
}

fn hash_fcc(f: EmbeddedCurveScalar, c1: EmbeddedCurvePoint, c2: EmbeddedCurvePoint) -> EmbeddedCurveScalar {
    let mut data: [u8; 160] = [0; 160];
    let flo: [u8; 16] = f.lo.to_le_bytes();
    let cur_pos = 0;
    for i in 0..16 {
        data[cur_pos + i as u32] = flo[i as u32];
    }
    let cur_pos = cur_pos + 16;
    let fhi: [u8; 16] = f.hi.to_le_bytes();
    for i in 0..16 {
        data[cur_pos + i as u32] = fhi[i as u32];
    }
    let cur_pos = cur_pos + 16;
    let c1_x_bytes: [u8; 32] = c1.x.to_le_bytes();
    for i in 0..32 {
        data[cur_pos + i as u32] = c1_x_bytes[i as u32];
    }
    let cur_pos = cur_pos + 32;
    let c1_y_bytes: [u8; 32] = c1.y.to_le_bytes();
    for i in 0..32 {
        data[cur_pos + i as u32] = c1_y_bytes[i as u32];
    }
    let cur_pos = cur_pos + 32;
    let c2_x_bytes: [u8; 32] = c2.x.to_le_bytes();
    for i in 0..32 {
        data[cur_pos + i as u32] = c2_x_bytes[i as u32];
    }
    let cur_pos = cur_pos + 32;
    let c2_y_bytes: [u8; 32] = c2.y.to_le_bytes();
    for i in 0..32 {
        data[cur_pos + i as u32] = c2_y_bytes[i as u32];
    }
    hash_to_field(data)
}

fn verify(msg : EmbeddedCurveScalar, sig: Signature, vk: EmbeddedCurvePoint) {
    let R0 = sig.theta.Z0 + multi_scalar_mul([-vk], [sig.sigma.c0]);
    let R1 = multi_scalar_mul([EmbeddedCurvePoint::generator(), -sig.theta.Z0], [sig.sigma.z1, sig.sigma.c1]);
    assert_eq(sig.sigma.c0, hash_fcc(sig.theta.m0, vk, R0));
    assert_eq(sig.sigma.c1, hash_fcc(msg, sig.theta.Z0, R1));
}

#[test]
fn test_verify() {
    let vk = EmbeddedCurvePoint {x: 7257076507064767502048399488283005105690152857237400700739974538328312070936, y: 18075790027769853990372100973781662593406554305622169619400137677165578621371, is_infinite: false};
    let msg = EmbeddedCurveScalar::new(0x8ebb80e28b3b550bb0c896fd707b04a4, 0x1cf11a08c8b67370342a65a130f3a8fd);
    let sigma = Sigma {
        c0: EmbeddedCurveScalar::new(0x3c668ab688d8873c75abdf4c072c8d22, 0x6ec948b8ecc10e6fe4c65546e4b6ae),
        c1: EmbeddedCurveScalar::new(0xc61bc89c55304b620e7c27807ae8f0cf, 0x227646ba5af507d943fb3439ee49ff),
        z1: EmbeddedCurveScalar::new(0x760c6b393c080a5f8fed35cd0a3b2ac3, 0x5c0ba00326f38773e76adf92597c4cc)
    };
    let theta = Theta {
        m0: EmbeddedCurveScalar::new(0xa40d7b071103757c1a03bd319dae9671, 0x2dd9aff98ee54ea96ec1ea12ea7b1515),
        Z0: EmbeddedCurvePoint {x: 12364409080910505570532105014962964930181657457138259606113159612669888195990, y: 11290227409238322764197919667336681608600871963378008195395309167662119348696, is_infinite: false}
    };
    let sig = Signature { sigma, theta };
    verify(msg, sig, vk);

}

#[test]
fn test_hash_to_field() {
    let mut slice : [u8;128] = [0;128];
    for i in 0..128 {
        slice[i as u32] = i;
    }
    print(hash_to_field(slice))
}

#[test]
fn blake2_test() {
    let mut slice : [u8;128] = [0;128];
    for i in 0..128 {
        slice[i as u32] = i;
    }
    print(blake2s(slice))
}

#[test]
fn hash_to_field_wrong() {
    let x = hash_to_field([1, 2]);
    let y = hash_to_field([2, 1]);
    assert_eq(x, y)
}

fn main(x: Field, y: pub Field) {
    assert(x != y);
}

#[test]
fn test_main() {
    main(1, 2);

    // Uncomment to make test fail
    // main(1, 1);
}
