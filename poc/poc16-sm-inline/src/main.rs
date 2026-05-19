//! POC 16 binary entry point. Runs all four runtime gates and reports
//! timings. Gate G-3.5 (`wasm32-unknown-unknown` build) is verified by
//! `cargo build --target wasm32-unknown-unknown -p poc16-sm-inline`,
//! which doesn't need this binary to run.

use poc16_sm_inline::scenarios::{
    gate_3_1_inline_keygen, gate_3_2_inline_auxinfo, gate_3_3_byte_identical_auxinfo,
    gate_3_4_at_rest_round_trip,
};

fn main() -> anyhow::Result<()> {
    println!("==== POC 16 — Phase G inline SM + Paillier pool ====");
    gate_3_1_inline_keygen()?;
    gate_3_2_inline_auxinfo()?;
    gate_3_3_byte_identical_auxinfo()?;
    gate_3_4_at_rest_round_trip()?;
    println!("ALL GATES PASS — Phase G design empirically validated.");
    Ok(())
}
