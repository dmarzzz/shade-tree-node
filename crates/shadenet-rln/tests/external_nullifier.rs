//! T-RUST-2d: pin the native `externalNullifier = poseidon2(epoch, rlnIdentifier)` to the
//! JS reference (`lib/rln.mjs` `externalNullifierFor`, rlnjs `calculateExternalNullifier`).
//! These decimals were produced by running `externalNullifierFor(epoch)` in node against
//! the pinned rlnjs; if the native poseidon2 or the epoch->Fr mapping ever drifts, the
//! gateway's cheap check-1 (`stale-external-nullifier`) would reject the Rust envelope, so
//! this fails first and loud.

use num_bigint::BigUint;
use shadenet_rln::tree::{external_nullifier, fr_to_dec};

fn id1() -> BigUint {
    BigUint::from(1u8)
}

#[test]
fn external_nullifier_matches_js_reference() {
    let cases: [(u64, &str); 4] = [
        (
            0,
            "12583541437132735734108669866114103169564651237895298778035846191048104863326",
        ),
        (
            1,
            "217234377348884654691879377518794323857294947151490278790710809376325639809",
        ),
        (
            42,
            "16556036937753546091282698062266362651008751416415631538814028886573393469713",
        ),
        (
            123456,
            "5532681754794517496156973461885797983202995308183279337354546645954408541838",
        ),
    ];
    for (epoch, want) in cases {
        let got = fr_to_dec(&external_nullifier(epoch, &id1()));
        assert_eq!(got, want, "externalNullifier(epoch={epoch}) drift");
    }
}
