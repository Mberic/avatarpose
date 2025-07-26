// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    DELTA = 4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant        R = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x0ae4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0ba4;

    uint256 internal constant                VK_MPTR = 0x05a0;
    uint256 internal constant         VK_DIGEST_MPTR = 0x05a0;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x05c0;
    uint256 internal constant                 K_MPTR = 0x05e0;
    uint256 internal constant             N_INV_MPTR = 0x0600;
    uint256 internal constant             OMEGA_MPTR = 0x0620;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0640;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0660;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0680;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x06a0;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x06c0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x06e0;
    uint256 internal constant              G1_X_MPTR = 0x0700;
    uint256 internal constant              G1_Y_MPTR = 0x0720;
    uint256 internal constant            G2_X_1_MPTR = 0x0740;
    uint256 internal constant            G2_X_2_MPTR = 0x0760;
    uint256 internal constant            G2_Y_1_MPTR = 0x0780;
    uint256 internal constant            G2_Y_2_MPTR = 0x07a0;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x07c0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x07e0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x0800;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0820;

    uint256 internal constant CHALLENGE_MPTR = 0x1200;

    uint256 internal constant THETA_MPTR = 0x1200;
    uint256 internal constant  BETA_MPTR = 0x1220;
    uint256 internal constant GAMMA_MPTR = 0x1240;
    uint256 internal constant     Y_MPTR = 0x1260;
    uint256 internal constant     X_MPTR = 0x1280;
    uint256 internal constant  ZETA_MPTR = 0x12a0;
    uint256 internal constant    NU_MPTR = 0x12c0;
    uint256 internal constant    MU_MPTR = 0x12e0;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1300;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x1320;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x1340;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x1360;
    uint256 internal constant             X_N_MPTR = 0x1380;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x13a0;
    uint256 internal constant          L_LAST_MPTR = 0x13c0;
    uint256 internal constant         L_BLIND_MPTR = 0x13e0;
    uint256 internal constant             L_0_MPTR = 0x1400;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x1420;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x1440;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x1460;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x1480;
    uint256 internal constant          R_EVAL_MPTR = 0x14a0;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x14c0;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x14e0;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1500;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x1520;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), R)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), R)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(R, 2))
                mstore(add(gp_mptr, 0xa0), R)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), R)
                    all_inv := mulmod(all_inv, mload(mptr), R)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), R)
                let inv_second := mulmod(all_inv, mload(first_mptr), R)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field 

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x05a0, 0x08d6705acefdbc2c4874c44ae417386cad6a0cb845d55560ce1f5c2470e20e4f) // vk_digest
                mstore(0x05c0, 0x00000000000000000000000000000000000000000000000000000000000000d4) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x1900, proof.length))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, instances.length))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := instances.offset
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := proof.offset
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0300) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0300) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0480) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0100) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0d00) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x05a0, 0x08d6705acefdbc2c4874c44ae417386cad6a0cb845d55560ce1f5c2470e20e4f) // vk_digest
                mstore(0x05c0, 0x00000000000000000000000000000000000000000000000000000000000000d4) // num_instances
                mstore(0x05e0, 0x0000000000000000000000000000000000000000000000000000000000000016) // k
                mstore(0x0600, 0x30644db14ff7d4a4f1cf9ed5406a7e5722d273a7aa184eaa5e1fb0846829b041) // n_inv
                mstore(0x0620, 0x18c95f1ae6514e11a1b30fd7923947c5ffcec5347f16e91b4dd654168326bede) // omega
                mstore(0x0640, 0x134f571fe34eb8c7b1685e875b324820e199bd70157493377cd65b204d1a3964) // omega_inv
                mstore(0x0660, 0x182fa146dab5070e1897c235ff7425a25d09f820206545e69bf946c2f6057429) // omega_inv_to_l
                mstore(0x0680, 0x0000000000000000000000000000000000000000000000000000000000000000) // has_accumulator
                mstore(0x06a0, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x06c0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limbs
                mstore(0x06e0, 0x0000000000000000000000000000000000000000000000000000000000000000) // num_acc_limb_bits
                mstore(0x0700, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0720, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0740, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0760, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0780, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x07a0, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x07c0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x07e0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x0800, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0820, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0840, 0x077aeee337c1fe30821a38185457b086eea1e4a7103b876047ceec449a36ce6a) // fixed_comms[0].x
                mstore(0x0860, 0x195babe8bad6e244ac7aecd619c07d316087cedfa3e7bba76c14013d8f1b60fb) // fixed_comms[0].y
                mstore(0x0880, 0x09f9597c887def34b6eacf59c39636b365ef327213859280c622f6425eb44799) // fixed_comms[1].x
                mstore(0x08a0, 0x2b7feb281321497d727ac5cc919fb876d37714dcf504bb74cd84d48e0fbfa1f0) // fixed_comms[1].y
                mstore(0x08c0, 0x11ca2b54fa705c380b67e6fb73b48e8e3daacf0ecaa82bddec9660000e0d2cca) // fixed_comms[2].x
                mstore(0x08e0, 0x210a1aaa0c938858e6347fdf48e06f711a5cff655dc3956a0a493e5304b4b0a1) // fixed_comms[2].y
                mstore(0x0900, 0x1584b450bed6fa2299cdc44dad6b34824a55d5387ccaa8853776e9fceae70c0b) // fixed_comms[3].x
                mstore(0x0920, 0x17ecef916dd01ae07ef1a0bc627739293fdeffccfa7fb2a84c4aa5d9c495a08a) // fixed_comms[3].y
                mstore(0x0940, 0x2f645a401d71a3c6a891deee88c9e01013cda516eda3599cb9637f99d6d286ab) // fixed_comms[4].x
                mstore(0x0960, 0x12dd97781c74c758914cb6250205ef14750ded6bdf8558e52a50f28b01270ed2) // fixed_comms[4].y
                mstore(0x0980, 0x2f645a401d71a3c6a891deee88c9e01013cda516eda3599cb9637f99d6d286ab) // fixed_comms[5].x
                mstore(0x09a0, 0x12dd97781c74c758914cb6250205ef14750ded6bdf8558e52a50f28b01270ed2) // fixed_comms[5].y
                mstore(0x09c0, 0x29b102e792efb0d335fd52ae4586fa075576c0fb2ce40b44c5b9ae80bd0ed526) // fixed_comms[6].x
                mstore(0x09e0, 0x19c04c074bbc34314ce7c1c2c3fa706ad46087795892cd9166f27c50f001c858) // fixed_comms[6].y
                mstore(0x0a00, 0x29b102e792efb0d335fd52ae4586fa075576c0fb2ce40b44c5b9ae80bd0ed526) // fixed_comms[7].x
                mstore(0x0a20, 0x19c04c074bbc34314ce7c1c2c3fa706ad46087795892cd9166f27c50f001c858) // fixed_comms[7].y
                mstore(0x0a40, 0x215db0c7812c44e7fd536be31326b08785c932af95ae599ac76e2ad80fd1de88) // fixed_comms[8].x
                mstore(0x0a60, 0x00521d2af600fe7d3bd0aef09c9c58fa40182eea7205dd1712974e0797bc9d9c) // fixed_comms[8].y
                mstore(0x0a80, 0x0e1b6bd63b70c1c4139e0fdd411642754cc23d05edee7b53ea4ca1817af61a4e) // fixed_comms[9].x
                mstore(0x0aa0, 0x0e9ea4ad760158670e63f60d892c66f9a393559093cf6840112173c3e7ac81c8) // fixed_comms[9].y
                mstore(0x0ac0, 0x0a09ffe724f083d77b74df024b0821265c632aaab4553eb991fa47b3ce3ea091) // fixed_comms[10].x
                mstore(0x0ae0, 0x11691ef09c812d987498a2b4c6e54630925ddda8c8e0c563b3894cf06cc3b249) // fixed_comms[10].y
                mstore(0x0b00, 0x0a09ffe724f083d77b74df024b0821265c632aaab4553eb991fa47b3ce3ea091) // fixed_comms[11].x
                mstore(0x0b20, 0x11691ef09c812d987498a2b4c6e54630925ddda8c8e0c563b3894cf06cc3b249) // fixed_comms[11].y
                mstore(0x0b40, 0x1d1127e558a58782b97b9f868c12abbcc3775be9fbe742aba4b93827b2782fdf) // fixed_comms[12].x
                mstore(0x0b60, 0x108afab0366e5fa58ec7adf83671b16805b87dd8d069829e305fa86f7c46c4bd) // fixed_comms[12].y
                mstore(0x0b80, 0x0ecb5beb20b96f58fa9a5556b99d8b783109e9d2a3d31c48579ee849330c1f0d) // fixed_comms[13].x
                mstore(0x0ba0, 0x113dbcd46e24e91d2a238f02fd793c7151b25980885ab07506446a9749d5d246) // fixed_comms[13].y
                mstore(0x0bc0, 0x03faed8d1be0d7b07d80f83ec3c17cdda3b066c46665367584acbde2202e14f1) // fixed_comms[14].x
                mstore(0x0be0, 0x1d5e4492cb70efd852bc22c4704cc95b49dc45d036b1ba16b436a5ba88e55ba3) // fixed_comms[14].y
                mstore(0x0c00, 0x03faed8d1be0d7b07d80f83ec3c17cdda3b066c46665367584acbde2202e14f1) // fixed_comms[15].x
                mstore(0x0c20, 0x1d5e4492cb70efd852bc22c4704cc95b49dc45d036b1ba16b436a5ba88e55ba3) // fixed_comms[15].y
                mstore(0x0c40, 0x14a60f476d022761612f55aed3584472e6c7a8b668fd120115426eb2cbb9571a) // fixed_comms[16].x
                mstore(0x0c60, 0x2f73d53470e78c2189344a159896918dcecff4b32673d9c21cb359ed1b82eb53) // fixed_comms[16].y
                mstore(0x0c80, 0x0d2725d6605dd221ae46c96683536c601b29e74c5a469074680e652dc73b5f19) // fixed_comms[17].x
                mstore(0x0ca0, 0x0d5c82c52a242815fc1ac8e516b2caf049979a58c02942524bb70bab5b570a65) // fixed_comms[17].y
                mstore(0x0cc0, 0x2f196e2411a8ed14d054588fe49df5f1ca14bae8d5ddfb17d892a1828d8facbc) // fixed_comms[18].x
                mstore(0x0ce0, 0x1c03d80322d58a86064ace5e98db6ba6c477264151ade000691a5972446902af) // fixed_comms[18].y
                mstore(0x0d00, 0x0f3ab1700c1e8b5e94e35fec36da3022802409658087be3d9879b12a511a553b) // fixed_comms[19].x
                mstore(0x0d20, 0x178dab30f65ff6ee8b8edeca9963befd8992839017c9d76270483fdc5078fe1b) // fixed_comms[19].y
                mstore(0x0d40, 0x0373d4c6bf34aea2a052b5b9a5ab126712e69c2645bbfd17b8060808ef4fd7df) // fixed_comms[20].x
                mstore(0x0d60, 0x02792e4008dae8d5c7495ed2aa89924e8c224be1ee0f5243bf03b8b23564383c) // fixed_comms[20].y
                mstore(0x0d80, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[21].x
                mstore(0x0da0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[21].y
                mstore(0x0dc0, 0x06d15f526588688c19bc8426e083b6807e8cd3ecaea67887adad9ea3c1cad62e) // fixed_comms[22].x
                mstore(0x0de0, 0x027564a775cf195b5ee11d8b1a9ecce057bc47db45cef45cfd4bab1d614798e2) // fixed_comms[22].y
                mstore(0x0e00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[23].x
                mstore(0x0e20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[23].y
                mstore(0x0e40, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[24].x
                mstore(0x0e60, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[24].y
                mstore(0x0e80, 0x1a675f158cc959fb1b810f356a10a85db4d540c0bf35a5afb0baac47b3fa9582) // permutation_comms[0].x
                mstore(0x0ea0, 0x068fea9ba083cd2d7e06a03e651728644214230ddb3d3d2e71e89e640959913c) // permutation_comms[0].y
                mstore(0x0ec0, 0x19987ec087924776dda5fc2da2afa126704b340b922b7ef70da2062b1b576e22) // permutation_comms[1].x
                mstore(0x0ee0, 0x268d80c093689b7eb181942750a3fd58b642796072270a46e2c92d5f2a8b2d33) // permutation_comms[1].y
                mstore(0x0f00, 0x18a16b47704e3eed6ecef92627d2f3c8910e87a14c5056b7c424594c58815b62) // permutation_comms[2].x
                mstore(0x0f20, 0x05760be5e623fc2b5fc79cc1c76ad6183011cbeb62f36b7e1d80c42863ef4b63) // permutation_comms[2].y
                mstore(0x0f40, 0x2d9e49fb32186c90f3bf90881e00da05b336c8db7b81263fc1ed5e79ee6235b2) // permutation_comms[3].x
                mstore(0x0f60, 0x03f2a858cadc488dcfa7cabd04a414a237f6016a5e92eb57109001f771e7a3be) // permutation_comms[3].y
                mstore(0x0f80, 0x2a04a6113718da4b3d2e5c978011b0b648826da11db038eae39268d2106944fc) // permutation_comms[4].x
                mstore(0x0fa0, 0x04ee3c98c181a0c410a334236825e1efd509929a8a9d11de57fc7a204d06b9ad) // permutation_comms[4].y
                mstore(0x0fc0, 0x036e28165254e7ad989c7d24ed5e9344e60726d07a8e6f323de51774b312a0b3) // permutation_comms[5].x
                mstore(0x0fe0, 0x1e3ecab86aa9e92946ec3083de72943576281032d1efe9266acc86a8ea1eb281) // permutation_comms[5].y
                mstore(0x1000, 0x0e00343cdd7d25f1a212c5fc0581a12fa3aaa5565acd1557c3c9ba1977f9798e) // permutation_comms[6].x
                mstore(0x1020, 0x0647fe944758624f0222b38bfae4f686b7f92b407380d1b2d590565c0c18365c) // permutation_comms[6].y
                mstore(0x1040, 0x0199319132cb6b11491dacc06a34f245e650610ad5148d5b7cff15935abcfc85) // permutation_comms[7].x
                mstore(0x1060, 0x290edb53b54f76090053d4523446be9852621415107164dca508d88acb6623f0) // permutation_comms[7].y
                mstore(0x1080, 0x17c3b8df037ca31add2b3354b7aa18ea721f6d012c76e59f8d47d4e84137d53b) // permutation_comms[8].x
                mstore(0x10a0, 0x0096c37e3b5916552b8a2d82d2ff0df600f5fb3c429e6d58bcae4a9859bd1a51) // permutation_comms[8].y
                mstore(0x10c0, 0x1373c448569b6251081266be4e10e34c51eaf258ca704c1454a0518700269e1b) // permutation_comms[9].x
                mstore(0x10e0, 0x1bf8b122a75720988fe7331c879cec30d9e53dd228e15ff14d1e3efea9f79664) // permutation_comms[9].y
                mstore(0x1100, 0x24593508aa4d987de30b2edf48ba57064911f094431d93afacaa8f80a9669b16) // permutation_comms[10].x
                mstore(0x1120, 0x23ab5412c9808e5e3308d03fed503e80bf1b625588910da47abcd5706a17dd96) // permutation_comms[10].y
                mstore(0x1140, 0x1c013b3a71dad5296ae503186e8038f325ac8fa22bd6578142a3b97f691e7525) // permutation_comms[11].x
                mstore(0x1160, 0x25256b8dae91600e7ec188c8de84831469740dc92805d3ce5a7b3bc54c1b5f51) // permutation_comms[11].y
                mstore(0x1180, 0x177d7e568ff4c350b7df296a55bb70002420a7610a4c230eca8e6cbb04a0b2cd) // permutation_comms[12].x
                mstore(0x11a0, 0x0d7d3420f29b64119c946966d1856acf81bc52a02d8295f48cfc42226e070f60) // permutation_comms[12].y
                mstore(0x11c0, 0x155445d079c7ea92520efb7f07d707cdc4c38f4f5d7f63a2a7051ce215b67e84) // permutation_comms[13].x
                mstore(0x11e0, 0x197374a0b159d1b8a5ae6dec492f1dea3d918af6c136c53a6daa6e0e19be9f22) // permutation_comms[13].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(instances.offset, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20))

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := instances.offset
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let y := mload(Y_MPTR)
                {
                    let f_16 := calldataload(0x0fa4)
                    let var0 := 0x2
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_0 := calldataload(0x0be4)
                    let a_4 := calldataload(0x0c64)
                    let var7 := addmod(a_0, a_4, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_8, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := var10
                }
                {
                    let f_17 := calldataload(0x0fc4)
                    let var0 := 0x2
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_9 := calldataload(0x0d04)
                    let a_1 := calldataload(0x0c04)
                    let a_5 := calldataload(0x0c84)
                    let var7 := addmod(a_1, a_5, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_9, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_18 := calldataload(0x0fe4)
                    let var0 := 0x2
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0d24)
                    let a_2 := calldataload(0x0c24)
                    let a_6 := calldataload(0x0ca4)
                    let var7 := addmod(a_2, a_6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_10, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_19 := calldataload(0x1004)
                    let var0 := 0x2
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_11 := calldataload(0x0d44)
                    let a_3 := calldataload(0x0c44)
                    let a_7 := calldataload(0x0cc4)
                    let var7 := addmod(a_3, a_7, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_11, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_16 := calldataload(0x0fa4)
                    let var0 := 0x1
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_0 := calldataload(0x0be4)
                    let a_4 := calldataload(0x0c64)
                    let var7 := mulmod(a_0, a_4, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_8, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_17 := calldataload(0x0fc4)
                    let var0 := 0x1
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_9 := calldataload(0x0d04)
                    let a_1 := calldataload(0x0c04)
                    let a_5 := calldataload(0x0c84)
                    let var7 := mulmod(a_1, a_5, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_9, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_18 := calldataload(0x0fe4)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0d24)
                    let a_2 := calldataload(0x0c24)
                    let a_6 := calldataload(0x0ca4)
                    let var7 := mulmod(a_2, a_6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_10, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_19 := calldataload(0x1004)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_11 := calldataload(0x0d44)
                    let a_3 := calldataload(0x0c44)
                    let a_7 := calldataload(0x0cc4)
                    let var7 := mulmod(a_3, a_7, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_11, var8, R)
                    let var10 := mulmod(var6, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_16 := calldataload(0x0fa4)
                    let var0 := 0x1
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_0 := calldataload(0x0be4)
                    let a_4 := calldataload(0x0c64)
                    let var7 := sub(R, a_4)
                    let var8 := addmod(a_0, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_8, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_17 := calldataload(0x0fc4)
                    let var0 := 0x1
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_9 := calldataload(0x0d04)
                    let a_1 := calldataload(0x0c04)
                    let a_5 := calldataload(0x0c84)
                    let var7 := sub(R, a_5)
                    let var8 := addmod(a_1, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_9, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_18 := calldataload(0x0fe4)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0d24)
                    let a_2 := calldataload(0x0c24)
                    let a_6 := calldataload(0x0ca4)
                    let var7 := sub(R, a_6)
                    let var8 := addmod(a_2, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_10, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_19 := calldataload(0x1004)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_11 := calldataload(0x0d44)
                    let a_3 := calldataload(0x0c44)
                    let a_7 := calldataload(0x0cc4)
                    let var7 := sub(R, a_7)
                    let var8 := addmod(a_3, var7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_11, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_20 := calldataload(0x1024)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_8_prev_1 := calldataload(0x0d64)
                    let var7 := 0x0
                    let a_0 := calldataload(0x0be4)
                    let a_4 := calldataload(0x0c64)
                    let var8 := mulmod(a_0, a_4, R)
                    let var9 := addmod(var7, var8, R)
                    let a_1 := calldataload(0x0c04)
                    let a_5 := calldataload(0x0c84)
                    let var10 := mulmod(a_1, a_5, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_8_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_8, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_22 := calldataload(0x1064)
                    let var0 := 0x1
                    let var1 := sub(R, f_22)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_22, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0d24)
                    let a_10_prev_1 := calldataload(0x0d84)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0c24)
                    let a_6 := calldataload(0x0ca4)
                    let var8 := mulmod(a_2, a_6, R)
                    let var9 := addmod(var7, var8, R)
                    let a_3 := calldataload(0x0c44)
                    let a_7 := calldataload(0x0cc4)
                    let var10 := mulmod(a_3, a_7, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_10_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_10, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_20 := calldataload(0x1024)
                    let var0 := 0x2
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let var7 := 0x0
                    let a_0 := calldataload(0x0be4)
                    let a_4 := calldataload(0x0c64)
                    let var8 := mulmod(a_0, a_4, R)
                    let var9 := addmod(var7, var8, R)
                    let a_1 := calldataload(0x0c04)
                    let a_5 := calldataload(0x0c84)
                    let var10 := mulmod(a_1, a_5, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_8, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_22 := calldataload(0x1064)
                    let var0 := 0x1
                    let var1 := sub(R, f_22)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_22, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0d24)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0c24)
                    let a_6 := calldataload(0x0ca4)
                    let var8 := mulmod(a_2, a_6, R)
                    let var9 := addmod(var7, var8, R)
                    let a_3 := calldataload(0x0c44)
                    let a_7 := calldataload(0x0cc4)
                    let var10 := mulmod(a_3, a_7, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_10, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_20 := calldataload(0x1024)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0c64)
                    let var7 := mulmod(var0, a_4, R)
                    let a_5 := calldataload(0x0c84)
                    let var8 := mulmod(var7, a_5, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_8, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_23 := calldataload(0x1084)
                    let var0 := 0x1
                    let var1 := sub(R, f_23)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_23, var2, R)
                    let a_10 := calldataload(0x0d24)
                    let a_6 := calldataload(0x0ca4)
                    let var4 := mulmod(var0, a_6, R)
                    let a_7 := calldataload(0x0cc4)
                    let var5 := mulmod(var4, a_7, R)
                    let var6 := sub(R, var5)
                    let var7 := addmod(a_10, var6, R)
                    let var8 := mulmod(var3, var7, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var8, r)
                }
                {
                    let f_21 := calldataload(0x1044)
                    let var0 := 0x2
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_8_prev_1 := calldataload(0x0d64)
                    let var4 := 0x1
                    let a_4 := calldataload(0x0c64)
                    let var5 := mulmod(var4, a_4, R)
                    let a_5 := calldataload(0x0c84)
                    let var6 := mulmod(var5, a_5, R)
                    let var7 := mulmod(a_8_prev_1, var6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_8, var8, R)
                    let var10 := mulmod(var3, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_23 := calldataload(0x1084)
                    let var0 := 0x2
                    let var1 := sub(R, f_23)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_23, var2, R)
                    let a_10 := calldataload(0x0d24)
                    let a_10_prev_1 := calldataload(0x0d84)
                    let var4 := 0x1
                    let a_6 := calldataload(0x0ca4)
                    let var5 := mulmod(var4, a_6, R)
                    let a_7 := calldataload(0x0cc4)
                    let var6 := mulmod(var5, a_7, R)
                    let var7 := mulmod(a_10_prev_1, var6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_10, var8, R)
                    let var10 := mulmod(var3, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_22 := calldataload(0x1064)
                    let var0 := 0x2
                    let var1 := sub(R, f_22)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_22, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0ce4)
                    let var7 := 0x0
                    let a_4 := calldataload(0x0c64)
                    let var8 := addmod(var7, a_4, R)
                    let a_5 := calldataload(0x0c84)
                    let var9 := addmod(var8, a_5, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_8, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_24 := calldataload(0x10a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_24)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_24, var2, R)
                    let a_10 := calldataload(0x0d24)
                    let var4 := 0x0
                    let a_6 := calldataload(0x0ca4)
                    let var5 := addmod(var4, a_6, R)
                    let a_7 := calldataload(0x0cc4)
                    let var6 := addmod(var5, a_7, R)
                    let var7 := sub(R, var6)
                    let var8 := addmod(a_10, var7, R)
                    let var9 := mulmod(var3, var8, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var9, r)
                }
                {
                    let f_21 := calldataload(0x1044)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let a_8 := calldataload(0x0ce4)
                    let a_8_prev_1 := calldataload(0x0d64)
                    let var4 := 0x0
                    let a_4 := calldataload(0x0c64)
                    let var5 := addmod(var4, a_4, R)
                    let a_5 := calldataload(0x0c84)
                    let var6 := addmod(var5, a_5, R)
                    let var7 := addmod(a_8_prev_1, var6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_8, var8, R)
                    let var10 := mulmod(var3, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_24 := calldataload(0x10a4)
                    let var0 := 0x2
                    let var1 := sub(R, f_24)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_24, var2, R)
                    let a_10 := calldataload(0x0d24)
                    let a_10_prev_1 := calldataload(0x0d84)
                    let var4 := 0x0
                    let a_6 := calldataload(0x0ca4)
                    let var5 := addmod(var4, a_6, R)
                    let a_7 := calldataload(0x0cc4)
                    let var6 := addmod(var5, a_7, R)
                    let var7 := addmod(a_10_prev_1, var6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_10, var8, R)
                    let var10 := mulmod(var3, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_4 := calldataload(0x0e24)
                    let var0 := 0x0
                    let var1 := mulmod(f_4, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_5 := calldataload(0x0e44)
                    let var0 := 0x0
                    let var1 := mulmod(f_5, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_6 := calldataload(0x0e64)
                    let var0 := 0x0
                    let var1 := mulmod(f_6, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_7 := calldataload(0x0e84)
                    let var0 := 0x0
                    let var1 := mulmod(f_7, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_8 := calldataload(0x0ea4)
                    let var0 := 0x0
                    let var1 := mulmod(f_8, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_9 := calldataload(0x0ec4)
                    let var0 := 0x0
                    let var1 := mulmod(f_9, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_10 := calldataload(0x0ee4)
                    let var0 := 0x0
                    let var1 := mulmod(f_10, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_11 := calldataload(0x0f04)
                    let var0 := 0x0
                    let var1 := mulmod(f_11, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_12 := calldataload(0x0f24)
                    let var0 := 0x0
                    let var1 := mulmod(f_12, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_13 := calldataload(0x0f44)
                    let var0 := 0x0
                    let var1 := mulmod(f_13, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_14 := calldataload(0x0f64)
                    let var0 := 0x0
                    let var1 := mulmod(f_14, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_15 := calldataload(0x0f84)
                    let var0 := 0x0
                    let var1 := mulmod(f_15, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(R, mulmod(l_0, calldataload(0x12a4), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x1424)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, R), sub(R, perm_z_last), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1304), sub(R, calldataload(0x12e4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1364), sub(R, calldataload(0x1344)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x13c4), sub(R, calldataload(0x13a4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1424), sub(R, calldataload(0x1404)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x12c4)
                    let rhs := calldataload(0x12a4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0be4), mulmod(beta, calldataload(0x10e4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c04), mulmod(beta, calldataload(0x1104), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c24), mulmod(beta, calldataload(0x1124), R), R), gamma, R), R)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0be4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1324)
                    let rhs := calldataload(0x1304)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c44), mulmod(beta, calldataload(0x1144), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c64), mulmod(beta, calldataload(0x1164), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0c84), mulmod(beta, calldataload(0x1184), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c44), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c64), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0c84), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1384)
                    let rhs := calldataload(0x1364)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ca4), mulmod(beta, calldataload(0x11a4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0cc4), mulmod(beta, calldataload(0x11c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ce4), mulmod(beta, calldataload(0x11e4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ca4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0cc4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ce4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x13e4)
                    let rhs := calldataload(0x13c4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d04), mulmod(beta, calldataload(0x1204), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d24), mulmod(beta, calldataload(0x1224), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d44), mulmod(beta, calldataload(0x1244), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0d04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0d24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0d44), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1444)
                    let rhs := calldataload(0x1424)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0da4), mulmod(beta, calldataload(0x1264), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x1284), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0da4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R), gamma, R), R)
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1464), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1464), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0dc4)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_4 := calldataload(0x0e24)
                        let var0 := 0x1
                        let var1 := mulmod(f_4, var0, R)
                        let a_0 := calldataload(0x0be4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x14a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1484), sub(R, calldataload(0x1464)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x14c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x14c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0dc4)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_5 := calldataload(0x0e44)
                        let var0 := 0x1
                        let var1 := mulmod(f_5, var0, R)
                        let a_1 := calldataload(0x0c04)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1504), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x14e4), sub(R, calldataload(0x14c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1524), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1524), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0dc4)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_6 := calldataload(0x0e64)
                        let var0 := 0x1
                        let var1 := mulmod(f_6, var0, R)
                        let a_2 := calldataload(0x0c24)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1564), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1544), sub(R, calldataload(0x1524)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1584), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1584), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_1 := calldataload(0x0dc4)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0e84)
                        let var0 := 0x1
                        let var1 := mulmod(f_7, var0, R)
                        let a_3 := calldataload(0x0c44)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x15c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x15a4), sub(R, calldataload(0x1584)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x15e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x15e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0de4)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x0ea4)
                        let var0 := 0x1
                        let var1 := mulmod(f_8, var0, R)
                        let a_0 := calldataload(0x0be4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1624), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1604), sub(R, calldataload(0x15e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1644), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1644), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0de4)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_9 := calldataload(0x0ec4)
                        let var0 := 0x1
                        let var1 := mulmod(f_9, var0, R)
                        let a_1 := calldataload(0x0c04)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1684), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1664), sub(R, calldataload(0x1644)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x16a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x16a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0de4)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_10 := calldataload(0x0ee4)
                        let var0 := 0x1
                        let var1 := mulmod(f_10, var0, R)
                        let a_2 := calldataload(0x0c24)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x16e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x16c4), sub(R, calldataload(0x16a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1704), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1704), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0de4)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_11 := calldataload(0x0f04)
                        let var0 := 0x1
                        let var1 := mulmod(f_11, var0, R)
                        let a_3 := calldataload(0x0c44)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1744), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1724), sub(R, calldataload(0x1704)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1764), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1764), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0e04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0f24)
                        let var0 := 0x1
                        let var1 := mulmod(f_12, var0, R)
                        let a_0 := calldataload(0x0be4)
                        let var2 := mulmod(var1, a_0, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x17a4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1784), sub(R, calldataload(0x1764)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x17c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x17c4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0e04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_13 := calldataload(0x0f44)
                        let var0 := 0x1
                        let var1 := mulmod(f_13, var0, R)
                        let a_1 := calldataload(0x0c04)
                        let var2 := mulmod(var1, a_1, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1804), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x17e4), sub(R, calldataload(0x17c4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1824), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1824), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0e04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_14 := calldataload(0x0f64)
                        let var0 := 0x1
                        let var1 := mulmod(f_14, var0, R)
                        let a_2 := calldataload(0x0c24)
                        let var2 := mulmod(var1, a_2, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1864), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1844), sub(R, calldataload(0x1824)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1884), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1884), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_3 := calldataload(0x0e04)
                        table := f_3
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_15 := calldataload(0x0f84)
                        let var0 := 0x1
                        let var1 := mulmod(f_15, var0, R)
                        let a_3 := calldataload(0x0c44)
                        let var2 := mulmod(var1, a_3, R)
                        let var3 := sub(R, var1)
                        let var4 := addmod(var0, var3, R)
                        let var5 := 0x0
                        let var6 := mulmod(var4, var5, R)
                        let var7 := addmod(var2, var6, R)
                        input_0 := var7
                        input_0 := addmod(input_0, beta, R)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x18c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x18a4), sub(R, calldataload(0x1884)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, R)
                    mstore(0x0360, x_pow_of_omega)
                    mstore(0x0340, x)
                    x_pow_of_omega := mulmod(x, omega_inv, R)
                    mstore(0x0320, x_pow_of_omega)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, R)
                    mstore(0x0300, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x0400
                            let point_mptr := 0x0300
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(R, mload(point_mptr)), R))
                    }
                    let s
                    s := mload(0x03c0)
                    mstore(0x0400, s)
                    let diff
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0420, diff)
                    mstore(0x00, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03e0), R)
                    mstore(0x0440, diff)
                    diff := mload(0x03a0)
                    mstore(0x0460, diff)
                    diff := mload(0x0380)
                    diff := mulmod(diff, mload(0x03a0), R)
                    mstore(0x0480, diff)
                }
                {
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x0320)
                    let point_2 := mload(0x0340)
                    let coeff
                    coeff := addmod(point_1, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03a0), R)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(R, point_1), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0300)
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_0, sub(R, point_2), R)
                    coeff := mulmod(coeff, addmod(point_0, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x0380), R)
                    mstore(0x80, coeff)
                    coeff := addmod(point_2, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_2, sub(R, point_3), R), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_3, sub(R, point_0), R)
                    coeff := mulmod(coeff, addmod(point_3, sub(R, point_2), R), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0xc0, coeff)
                }
                {
                    let point_2 := mload(0x0340)
                    let point_3 := mload(0x0360)
                    let coeff
                    coeff := addmod(point_2, sub(R, point_3), R)
                    coeff := mulmod(coeff, mload(0x03c0), R)
                    mstore(0xe0, coeff)
                    coeff := addmod(point_3, sub(R, point_2), R)
                    coeff := mulmod(coeff, mload(0x03e0), R)
                    mstore(0x0100, coeff)
                }
                {
                    success := batch_invert(success, 0, 0x0120)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0420, diff_0_inv)
                    for
                        {
                            let mptr := 0x0440
                            let mptr_end := 0x04a0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x10c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R), R)
                    for
                        {
                            let mptr := 0x1284
                            let mptr_end := 0x10c4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x10a4
                            let mptr_end := 0x0d84
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x18c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1864), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1804), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x17a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1744), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x16e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1684), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1624), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x15c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1564), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1504), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x14a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0d44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0d04), R), R)
                    for
                        {
                            let mptr := 0x0cc4
                            let mptr_end := 0x0bc4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    mstore(0x04a0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0d84), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0d24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0d64), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0ce4), R), R)
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1404), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x13c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x13e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x13a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1364), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1384), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1344), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1304), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1324), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x12e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x12a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x12c4), R), R)
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1884), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x18a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1824), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1844), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x17c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x17e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1764), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1784), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1704), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1724), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x16a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x16c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1644), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1664), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x15e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1604), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1584), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x15a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1524), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1544), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x14c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x14e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1464), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1484), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1424), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1444), R), R)
                    r_eval := mulmod(r_eval, mload(0x0480), R)
                    mstore(0x0500, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0520, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), R)
                    mstore(0x0540, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), R)
                    sum := addmod(sum, mload(0xc0), R)
                    mstore(0x0560, sum)
                }
                {
                    let sum := mload(0xe0)
                    sum := addmod(sum, mload(0x0100), R)
                    mstore(0x0580, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x80
                            let sum_mptr := 0x0520
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x80)
                    let r_eval := mulmod(mload(0x60), mload(0x0500), R)
                    for
                        {
                            let sum_inv_mptr := 0x40
                            let sum_inv_mptr_end := 0x80
                            let r_eval_mptr := 0x04e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), R)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), R), R)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x0aa4))
                    mstore(0x20, calldataload(0x0ac4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x11c0
                            let mptr_end := 0x0800
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0624
                            let mptr_end := 0x02e4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, calldataload(0x02a4), calldataload(0x02c4))
                    for
                        {
                            let mptr := 0x0224
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x02e4))
                    mstore(0xa0, calldataload(0x0304))
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0264), calldataload(0x0284))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0440), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x0724))
                    mstore(0xa0, calldataload(0x0744))
                    for
                        {
                            let mptr := 0x06e4
                            let mptr_end := 0x0624
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0460), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), R)
                    mstore(0x80, calldataload(0x0a64))
                    mstore(0xa0, calldataload(0x0a84))
                    for
                        {
                            let mptr := 0x0a24
                            let mptr_end := 0x0724
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0480), R))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(R, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x18e4))
                    mstore(0xa0, calldataload(0x1904))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1924))
                    mstore(0xa0, calldataload(0x1944))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x1924))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x1944))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}