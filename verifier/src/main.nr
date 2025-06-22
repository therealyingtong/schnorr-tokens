mod types;
mod schnorr_token;

use dep::aztec::macros::aztec;

// Minimal token contract. Do not use
// For demonstration purposes in playground only
// If you change the names of these functions, please also update them in playground/src/components/contract/contract.ts

#[aztec]
pub contract SimpleToken {
    use std::{meta::derive, ops::{Add, Sub}, embedded_curve_ops::{EmbeddedCurveScalar, EmbeddedCurvePoint}};

    use dep::compressed_string::FieldCompressedString;

    use dep::aztec::{
        context::{PrivateCallInterface, PrivateContext},
        event::event_interface::EventInterface,
        macros::{
            events::event,
            functions::{initializer, internal, private, public, utility, view},
            storage::storage,
        },
        messages::logs::{
            event::encode_and_encrypt_event_unconstrained,
            note::{encode_and_encrypt_note, encode_and_encrypt_note_unconstrained},
        },
        prelude::{AztecAddress, Map, PublicContext, PublicImmutable, PublicMutable, PrivateSet},
        protocol_types::traits::Serialize,
    };

    use dep::uint_note::uint_note::{PartialUintNote, UintNote};

    use dep::authwit::auth::{
        assert_current_call_valid_authwit, assert_current_call_valid_authwit_public,
        compute_authwit_nullifier,
    };

    use crate::types::balance_set::BalanceSet;
    use crate::schnorr_token::{Sigma, Theta, Signature, verify};

    global INITIAL_TRANSFER_CALL_MAX_NOTES: u32 = 2;
    global RECURSIVE_TRANSFER_CALL_MAX_NOTES: u32 = 8;

    #[derive(Serialize)]
    #[event]
    struct Transfer {
        from: AztecAddress,
        to: AztecAddress,
        amount: u128,
    }

    #[storage]
    struct Storage<Context> {
        balances: Map<AztecAddress, BalanceSet<Context>, Context>,
        public_balances: Map<AztecAddress, PublicMutable<u128, Context>, Context>,
        revoked: Map<Field, PublicMutable<Field, Context>, Context>,
        symbol: PublicImmutable<FieldCompressedString, Context>,
        name: PublicImmutable<FieldCompressedString, Context>,
        decimals: PublicImmutable<u8, Context>,
    }

    #[public]
    #[initializer]
    fn constructor(name: str<31>, symbol: str<31>, decimals: u8) {
        storage.name.initialize(FieldCompressedString::from_string(name));
        storage.symbol.initialize(FieldCompressedString::from_string(symbol));
        storage.decimals.initialize(decimals);
    }

    #[public]
    #[view]
    fn public_balance_of(owner: AztecAddress) -> u128 {
        storage.public_balances.at(owner).read()
    }
   
    #[public]
    fn public_transfer(
        to: AztecAddress,
        amount: u128,
        msg_lo: Field,
        msg_hi: Field,
        c0_lo: Field,
        c0_hi: Field,
        c1_lo: Field,
        c1_hi: Field,
        z1_lo: Field,
        z1_hi: Field,
        m0_lo: Field,
        m0_hi: Field,
        z0_x: Field,
        z0_y: Field,
    ) {
        assert(storage.revoked.at(m0_lo).read() == 0, "c0 already used");

        let vk = EmbeddedCurvePoint {x: 7257076507064767502048399488283005105690152857237400700739974538328312070936, y: 18075790027769853990372100973781662593406554305622169619400137677165578621371, is_infinite: false};

        let msg = EmbeddedCurveScalar::new(msg_lo, msg_hi);
        let sigma = Sigma {
            c0: EmbeddedCurveScalar::new(c0_lo, c0_hi),
            c1: EmbeddedCurveScalar::new(c1_lo, c1_hi),
            z1: EmbeddedCurveScalar::new(z1_lo, z1_hi),
        };
        let theta = Theta {
            m0: EmbeddedCurveScalar::new(m0_lo, m0_hi),
            Z0: EmbeddedCurvePoint {x: z0_x, y: z0_y, is_infinite: false}
        };
        let sig = Signature { sigma, theta };
        verify(msg, sig, vk);

        let to_balance = storage.public_balances.at(to).read().add(amount);
        storage.public_balances.at(to).write(to_balance);

        storage.revoked
            .at(m0_lo)
            .write(Field::from(1));
    }
}