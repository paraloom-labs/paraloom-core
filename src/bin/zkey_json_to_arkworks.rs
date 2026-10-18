//! Convert a snarkjs Groth16 proving key into an arkworks `ProvingKey<Bn254>`.
//!
//! The mainnet ceremony runs in snarkjs on a public powers-of-tau transcript
//! (#659), which leaves the finalized key in a `.zkey`. Our prover is
//! arkworks, so the key has to cross over once, offline, at cutover:
//!
//! ```text
//! snarkjs zkey export json final.zkey final.json
//! cargo run --release --bin zkey_json_to_arkworks -- final.json keys/transact_v3_proving.key
//! ```
//!
//! Going through `zkey export json` rather than parsing the `.zkey` directly
//! is deliberate: the binary format stores points in Montgomery form inside
//! typed sections, and every one of those details is a chance to be subtly
//! wrong. The JSON is decimal strings, and snarkjs owns the decoding.
//!
//! A key converted this way is a *circom-convention* key: circom prepares the
//! powers of tau in Lagrange basis, so proofs must be generated with
//! [`CircomReduction`](paraloom::privacy::circom_reduction::CircomReduction)
//! rather than arkworks' default. Verification is unaffected — it is pairings
//! against the verifying key and knows nothing about the QAP reduction.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use serde::Deserialize;
use std::str::FromStr;

/// `[x, y, z]` as decimal strings. snarkjs emits `z = 1` for a normal point
/// and `z = 0` for the identity.
type G1Json = [String; 3];
/// `[[x0, x1], [y0, y1], [z0, z1]]`, same convention over the quadratic
/// extension.
type G2Json = [[String; 2]; 3];

#[derive(Deserialize)]
struct ZkeyJson {
    protocol: String,
    q: String,
    r: String,
    #[serde(rename = "nVars")]
    num_vars: usize,
    #[serde(rename = "nPublic")]
    num_public: usize,
    #[serde(rename = "domainSize")]
    domain_size: usize,
    vk_alpha_1: G1Json,
    vk_beta_1: G1Json,
    vk_beta_2: G2Json,
    vk_gamma_2: G2Json,
    vk_delta_1: G1Json,
    vk_delta_2: G2Json,
    #[serde(rename = "IC")]
    ic: Vec<G1Json>,
    #[serde(rename = "A")]
    a: Vec<G1Json>,
    #[serde(rename = "B1")]
    b1: Vec<G1Json>,
    #[serde(rename = "B2")]
    b2: Vec<G2Json>,
    /// One entry per variable, `null` for the public ones — those have no
    /// `l_query` term.
    #[serde(rename = "C")]
    c: Vec<Option<G1Json>>,
    #[serde(rename = "hExps")]
    h_exps: Vec<G1Json>,
}

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn fq(s: &str) -> Res<Fq> {
    Fq::from_str(s).map_err(|_| format!("not a base-field element: {}", s).into())
}

/// Reject anything that is not on the curve or not in the prime-order
/// subgroup. A malformed point would otherwise surface much later as an
/// unprovable key.
fn check_g1(p: G1Affine, what: &str) -> Res<G1Affine> {
    if !p.is_on_curve() {
        return Err(format!("{} is not on the curve", what).into());
    }
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!("{} is not in the prime-order subgroup", what).into());
    }
    Ok(p)
}

fn g1(p: &G1Json, what: &str) -> Res<G1Affine> {
    let z = fq(&p[2])?;
    if z.is_zero() {
        return Ok(G1Affine::identity());
    }
    if z != Fq::ONE {
        return Err(format!("{}: expected z of 0 or 1, got {}", what, p[2]).into());
    }
    check_g1(G1Affine::new_unchecked(fq(&p[0])?, fq(&p[1])?), what)
}

fn g1_non_zero(p: &G1Json, what: &str) -> Res<G1Affine> {
    let point = g1(p, what)?;
    if point.is_zero() {
        return Err(format!("{} must not be the point at infinity", what).into());
    }
    Ok(point)
}

fn g2(p: &G2Json, what: &str) -> Res<G2Affine> {
    let z = Fq2::new(fq(&p[2][0])?, fq(&p[2][1])?);
    if z.is_zero() {
        return Ok(G2Affine::identity());
    }
    if z != Fq2::ONE {
        return Err(format!("{}: expected z of 0 or 1", what).into());
    }
    let point = G2Affine::new_unchecked(
        Fq2::new(fq(&p[0][0])?, fq(&p[0][1])?),
        Fq2::new(fq(&p[1][0])?, fq(&p[1][1])?),
    );
    if !point.is_on_curve() {
        return Err(format!("{} is not on the curve", what).into());
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!("{} is not in the prime-order subgroup", what).into());
    }
    Ok(point)
}

fn g2_non_zero(p: &G2Json, what: &str) -> Res<G2Affine> {
    let point = g2(p, what)?;
    if point.is_zero() {
        return Err(format!("{} must not be the point at infinity", what).into());
    }
    Ok(point)
}

fn g1_vec(points: &[G1Json], what: &str) -> Res<Vec<G1Affine>> {
    points
        .iter()
        .enumerate()
        .map(|(i, p)| g1(p, &format!("{}[{}]", what, i)))
        .collect()
}

fn convert_zkey_json(zkey: ZkeyJson) -> Res<ProvingKey<Bn254>> {
    if zkey.protocol != "groth16" {
        return Err(format!("expected a groth16 key, got {}", zkey.protocol).into());
    }
    // The curve is implied by every point we are about to build, so confirm it
    // before building any of them.
    if zkey.r != Fr::MODULUS.to_string() || zkey.q != Fq::MODULUS.to_string() {
        return Err("key is not over BN254".into());
    }
    let expected_ic_len = zkey
        .num_public
        .checked_add(1)
        .ok_or("nPublic overflow")?;
    if zkey.ic.len() != expected_ic_len {
        return Err(format!(
            "IC has {} points, expected nPublic + 1 = {}",
            zkey.ic.len(),
            expected_ic_len
        )
        .into());
    }
    if zkey.num_vars < zkey.ic.len() {
        return Err(format!(
            "nVars ({}) must be at least IC length ({})",
            zkey.num_vars,
            zkey.ic.len()
        )
        .into());
    }
    for (name, len) in [
        ("A", zkey.a.len()),
        ("B1", zkey.b1.len()),
        ("B2", zkey.b2.len()),
        ("C", zkey.c.len()),
    ] {
        if len != zkey.num_vars {
            return Err(format!(
                "{} has {} points, expected nVars = {}",
                name, len, zkey.num_vars
            )
            .into());
        }
    }
    if zkey.domain_size == 0 {
        return Err("domainSize must be non-zero".into());
    }
    if zkey.h_exps.len() != zkey.domain_size {
        return Err(format!(
            "hExps has {} points, expected domainSize = {}",
            zkey.h_exps.len(),
            zkey.domain_size
        )
        .into());
    }

    // `C` carries a hole for every public wire; the remainder is `l_query`,
    // in order. Anything else means the file does not describe the layout we
    // think it does.
    let mut l_query = Vec::with_capacity(zkey.num_vars - zkey.ic.len());
    for (i, entry) in zkey.c.iter().enumerate() {
        match entry {
            None if i < zkey.ic.len() => {}
            None => return Err(format!("C[{}] is null past the public wires", i).into()),
            Some(_) if i < zkey.ic.len() => {
                return Err(format!("C[{}] is set for a public wire", i).into())
            }
            Some(p) => l_query.push(g1(p, &format!("C[{}]", i))?),
        }
    }

    let pk = ProvingKey::<Bn254> {
        vk: VerifyingKey {
            alpha_g1: g1_non_zero(&zkey.vk_alpha_1, "vk_alpha_1")?,
            beta_g2: g2_non_zero(&zkey.vk_beta_2, "vk_beta_2")?,
            gamma_g2: g2_non_zero(&zkey.vk_gamma_2, "vk_gamma_2")?,
            delta_g2: g2_non_zero(&zkey.vk_delta_2, "vk_delta_2")?,
            gamma_abc_g1: g1_vec(&zkey.ic, "IC")?,
        },
        beta_g1: g1_non_zero(&zkey.vk_beta_1, "vk_beta_1")?,
        delta_g1: g1_non_zero(&zkey.vk_delta_1, "vk_delta_1")?,
        a_query: g1_vec(&zkey.a, "A")?,
        b_g1_query: g1_vec(&zkey.b1, "B1")?,
        b_g2_query: zkey
            .b2
            .iter()
            .enumerate()
            .map(|(i, p)| g2(p, &format!("B2[{}]", i)))
            .collect::<Res<Vec<_>>>()?,
        h_query: g1_vec(&zkey.h_exps, "hExps")?,
        l_query,
    };

    // Enforce cross-group discrete-log consistency between G1 and G2 toxic-waste
    // terms: e(beta_g1, G2) == e(G1, vk.beta_g2) and e(delta_g1, G2) == e(G1, vk.delta_g2).
    if Bn254::pairing(pk.beta_g1, G2Affine::generator())
        != Bn254::pairing(G1Affine::generator(), pk.vk.beta_g2)
    {
        return Err("vk_beta_1 and vk_beta_2 do not share the same discrete logarithm".into());
    }
    if Bn254::pairing(pk.delta_g1, G2Affine::generator())
        != Bn254::pairing(G1Affine::generator(), pk.vk.delta_g2)
    {
        return Err("vk_delta_1 and vk_delta_2 do not share the same discrete logarithm".into());
    }

    Ok(pk)
}

fn main() -> Res<()> {
    env_logger::init();

    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .ok_or("usage: zkey_json_to_arkworks <zkey.json> <out.key>")?;
    let output = args
        .next()
        .ok_or("usage: zkey_json_to_arkworks <zkey.json> <out.key> [<vk.key>]")?;
    // Optional third arg: also write the verifying key. The VK is embedded in
    // the proving key we build (`pk.vk`), but `emit_transact_v3_fixture` reads
    // it from a separate file. Without this the ceremony produces a proving key
    // and no arkworks VK, and the runbook's cut-the-VK step has no input —
    // exactly the gap hit at the transact v3 cutover.
    let vk_output = args.next();

    println!("Reading {}...", input);
    let zkey: ZkeyJson =
        serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(&input)?))?;

    println!(
        "Converting {} variables, {} public inputs, domain {}...",
        zkey.num_vars, zkey.num_public, zkey.domain_size
    );
    println!("(every point is checked on-curve and in-subgroup)");

    let pk = convert_zkey_json(zkey)?;

    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)?;
    std::fs::write(&output, &bytes)?;

    if let Some(vk_path) = vk_output {
        // The same VK the on-chain program embeds. Serialized from `pk.vk`, so
        // it cannot disagree with the proving key it was extracted from.
        let mut vk_bytes = Vec::new();
        pk.vk.serialize_compressed(&mut vk_bytes)?;
        std::fs::write(&vk_path, &vk_bytes)?;
        println!(
            "Wrote {} ({} bytes, verifying key)",
            vk_path,
            vk_bytes.len()
        );
    }

    println!("\nWrote {} ({} bytes)", output, bytes.len());
    println!("  a_query   {}", pk.a_query.len());
    println!("  b_g2_query {}", pk.b_g2_query.len());
    println!("  l_query   {}", pk.l_query.len());
    println!("  h_query   {}", pk.h_query.len());
    println!("  IC        {}", pk.vk.gamma_abc_g1.len());
    println!("\nThis is a circom-convention key: prove with CircomReduction.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;

    fn g1_to_json(p: G1Affine) -> G1Json {
        if p.is_zero() {
            ["0".to_string(), "1".to_string(), "0".to_string()]
        } else {
            let (x, y) = p.xy().unwrap();
            [x.to_string(), y.to_string(), "1".to_string()]
        }
    }

    fn g2_to_json(p: G2Affine) -> G2Json {
        if p.is_zero() {
            [
                ["0".to_string(), "0".to_string()],
                ["1".to_string(), "0".to_string()],
                ["0".to_string(), "0".to_string()],
            ]
        } else {
            let (x, y) = p.xy().unwrap();
            [
                [x.c0.to_string(), x.c1.to_string()],
                [y.c0.to_string(), y.c1.to_string()],
                ["1".to_string(), "0".to_string()],
            ]
        }
    }

    fn valid_fixture() -> ZkeyJson {
        let g1_gen = G1Affine::generator();
        let g2_gen = G2Affine::generator();
        let alpha = Fr::from(2u64);
        let beta = Fr::from(3u64);
        let gamma = Fr::from(5u64);
        let delta = Fr::from(7u64);

        ZkeyJson {
            protocol: "groth16".to_string(),
            q: Fq::MODULUS.to_string(),
            r: Fr::MODULUS.to_string(),
            num_vars: 4,
            num_public: 1,
            domain_size: 2,
            vk_alpha_1: g1_to_json((g1_gen * alpha).into_affine()),
            vk_beta_1: g1_to_json((g1_gen * beta).into_affine()),
            vk_beta_2: g2_to_json((g2_gen * beta).into_affine()),
            vk_gamma_2: g2_to_json((g2_gen * gamma).into_affine()),
            vk_delta_1: g1_to_json((g1_gen * delta).into_affine()),
            vk_delta_2: g2_to_json((g2_gen * delta).into_affine()),
            ic: vec![g1_to_json(g1_gen), g1_to_json(g1_gen)],
            a: vec![
                g1_to_json(g1_gen),
                g1_to_json(G1Affine::identity()),
                g1_to_json(g1_gen),
                g1_to_json(g1_gen),
            ],
            b1: vec![
                g1_to_json(g1_gen),
                g1_to_json(g1_gen),
                g1_to_json(G1Affine::identity()),
                g1_to_json(g1_gen),
            ],
            b2: vec![
                g2_to_json(g2_gen),
                g2_to_json(g2_gen),
                g2_to_json(G2Affine::identity()),
                g2_to_json(g2_gen),
            ],
            c: vec![
                None,
                None,
                Some(g1_to_json(g1_gen)),
                Some(g1_to_json(g1_gen)),
            ],
            h_exps: vec![g1_to_json(g1_gen), g1_to_json(g1_gen)],
        }
    }

    #[test]
    fn valid_zkey_json_converts_successfully() {
        let pk = convert_zkey_json(valid_fixture()).expect("valid fixture converts");
        assert_eq!(pk.l_query.len(), 2);
        assert_eq!(pk.h_query.len(), 2);
    }

    #[test]
    fn truncated_c_array_is_rejected() {
        let mut zkey = valid_fixture();
        zkey.c.pop();
        let err = convert_zkey_json(zkey).expect_err("truncated C array must be rejected");
        assert!(err.to_string().contains("C has 3 points, expected nVars = 4"));
    }

    #[test]
    fn num_vars_smaller_than_ic_len_returns_error_without_panic() {
        let mut zkey = valid_fixture();
        zkey.num_vars = 1; // ic.len() is 2 (nPublic = 1)
        let err = convert_zkey_json(zkey).expect_err("nVars < IC.len() must not underflow-panic");
        assert!(err.to_string().contains("nVars (1) must be at least IC length (2)"));
    }

    #[test]
    fn identity_point_in_vk_or_pk_toxic_waste_terms_is_rejected() {
        let mut zkey = valid_fixture();
        zkey.vk_delta_2 = g2_to_json(G2Affine::identity());
        let err = convert_zkey_json(zkey).expect_err("zero vk_delta_2 must be rejected");
        assert!(err
            .to_string()
            .contains("vk_delta_2 must not be the point at infinity"));
    }

    #[test]
    fn mismatched_delta_g1_and_delta_g2_discrete_logs_are_rejected() {
        let mut zkey = valid_fixture();
        let g1_gen = G1Affine::generator();
        zkey.vk_delta_1 = g1_to_json((g1_gen * Fr::from(99u64)).into_affine());
        let err = convert_zkey_json(zkey).expect_err("mismatched delta_1/delta_2 must fail");
        assert!(err
            .to_string()
            .contains("vk_delta_1 and vk_delta_2 do not share the same discrete logarithm"));
    }

    #[test]
    fn mismatched_beta_g1_and_beta_g2_discrete_logs_are_rejected() {
        let mut zkey = valid_fixture();
        let g1_gen = G1Affine::generator();
        zkey.vk_beta_1 = g1_to_json((g1_gen * Fr::from(77u64)).into_affine());
        let err = convert_zkey_json(zkey).expect_err("mismatched beta_1/beta_2 must fail");
        assert!(err
            .to_string()
            .contains("vk_beta_1 and vk_beta_2 do not share the same discrete logarithm"));
    }
}
