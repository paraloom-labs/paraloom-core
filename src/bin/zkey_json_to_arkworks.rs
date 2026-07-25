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

fn g1_vec(points: &[G1Json], what: &str) -> Res<Vec<G1Affine>> {
    points
        .iter()
        .enumerate()
        .map(|(i, p)| g1(p, &format!("{}[{}]", what, i)))
        .collect()
}

fn main() -> Res<()> {
    env_logger::init();

    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .ok_or("usage: zkey_json_to_arkworks <zkey.json> <out.key>")?;
    let output = args
        .next()
        .ok_or("usage: zkey_json_to_arkworks <zkey.json> <out.key>")?;

    println!("Reading {}...", input);
    let zkey: ZkeyJson =
        serde_json::from_reader(std::io::BufReader::new(std::fs::File::open(&input)?))?;

    if zkey.protocol != "groth16" {
        return Err(format!("expected a groth16 key, got {}", zkey.protocol).into());
    }
    // The curve is implied by every point we are about to build, so confirm it
    // before building any of them.
    if zkey.r != Fr::MODULUS.to_string() || zkey.q != Fq::MODULUS.to_string() {
        return Err("key is not over BN254".into());
    }
    if zkey.ic.len() != zkey.num_public + 1 {
        return Err(format!(
            "IC has {} points, expected nPublic + 1 = {}",
            zkey.ic.len(),
            zkey.num_public + 1
        )
        .into());
    }
    for (name, len) in [
        ("A", zkey.a.len()),
        ("B1", zkey.b1.len()),
        ("B2", zkey.b2.len()),
    ] {
        if len != zkey.num_vars {
            return Err(format!(
                "{} has {} points, expected nVars = {}",
                name, len, zkey.num_vars
            )
            .into());
        }
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

    println!(
        "Converting {} variables, {} public inputs, domain {}...",
        zkey.num_vars, zkey.num_public, zkey.domain_size
    );
    println!("(every point is checked on-curve and in-subgroup)");

    let pk = ProvingKey::<Bn254> {
        vk: VerifyingKey {
            alpha_g1: g1(&zkey.vk_alpha_1, "vk_alpha_1")?,
            beta_g2: g2(&zkey.vk_beta_2, "vk_beta_2")?,
            gamma_g2: g2(&zkey.vk_gamma_2, "vk_gamma_2")?,
            delta_g2: g2(&zkey.vk_delta_2, "vk_delta_2")?,
            gamma_abc_g1: g1_vec(&zkey.ic, "IC")?,
        },
        beta_g1: g1(&zkey.vk_beta_1, "vk_beta_1")?,
        delta_g1: g1(&zkey.vk_delta_1, "vk_delta_1")?,
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

    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)?;
    std::fs::write(&output, &bytes)?;

    println!("\nWrote {} ({} bytes)", output, bytes.len());
    println!("  a_query   {}", pk.a_query.len());
    println!("  b_g2_query {}", pk.b_g2_query.len());
    println!("  l_query   {}", pk.l_query.len());
    println!("  h_query   {}", pk.h_query.len());
    println!("  IC        {}", pk.vk.gamma_abc_g1.len());
    println!("\nThis is a circom-convention key: prove with CircomReduction.");

    Ok(())
}
