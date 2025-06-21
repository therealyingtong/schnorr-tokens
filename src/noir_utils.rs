use crate::an23_proxy_signature::Signature;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_grumpkin::{Fr, Projective};

pub fn grumpkin_fr_to_nr_code(fr: ark_grumpkin::Fr) -> String {
    let bi = fr.into_bigint().0;
    let lo: u128 = (bi[0] as u128) | (bi[1] as u128) << 64;
    let hi: u128 = (bi[2] as u128) | (bi[3] as u128) << 64;
    format!("EmbeddedCurveScalar::new(0x{:x}, 0x{:x})", lo, hi)
}

pub fn grumpkin_point_to_nr_code(point: ark_grumpkin::Projective) -> String {
    let aff = point.into_affine();
    format!(
        "EmbeddedCurvePoint {{x: {}, y: {}, is_infinite: false}}",
        aff.x().unwrap(),
        aff.y().unwrap()
    )
    .to_string()
}

pub fn grumpkin_sig_to_nr_code(signature: &Signature<ark_grumpkin::Projective>) -> String {
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
