// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    DELTA = 4131629893567559867359510883348571134090853742863529169391034518566172092834;
    uint256 internal constant        R = 21888242871839275222246405745257275088548364400416034343698204186575808495617; 

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x0ba4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x0ca4;

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

    uint256 internal constant CHALLENGE_MPTR = 0x1240;

    uint256 internal constant THETA_MPTR = 0x1240;
    uint256 internal constant  BETA_MPTR = 0x1260;
    uint256 internal constant GAMMA_MPTR = 0x1280;
    uint256 internal constant     Y_MPTR = 0x12a0;
    uint256 internal constant     X_MPTR = 0x12c0;
    uint256 internal constant  ZETA_MPTR = 0x12e0;
    uint256 internal constant    NU_MPTR = 0x1300;
    uint256 internal constant    MU_MPTR = 0x1320;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x1340;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x1360;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x1380;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x13a0;
    uint256 internal constant             X_N_MPTR = 0x13c0;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x13e0;
    uint256 internal constant          L_LAST_MPTR = 0x1400;
    uint256 internal constant         L_BLIND_MPTR = 0x1420;
    uint256 internal constant             L_0_MPTR = 0x1440;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x1460;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x1480;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x14a0;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x14c0;
    uint256 internal constant          R_EVAL_MPTR = 0x14e0;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x1500;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x1520;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x1540;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x1560;

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
                mstore(0x05a0, 0x22edd11078b58fad4890164a9810b2dec76fb819dba2a756e16b382b3ddac4cf) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000010d80) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x1a80, proof.length))

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
                    { let proof_cptr_end := add(proof_cptr, 0x03c0) }
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
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0d80) }
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
                mstore(0x05a0, 0x22edd11078b58fad4890164a9810b2dec76fb819dba2a756e16b382b3ddac4cf) // vk_digest
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000010d80) // num_instances
                mstore(0x05e0, 0x0000000000000000000000000000000000000000000000000000000000000017) // k
                mstore(0x0600, 0x30644e121894ba67550ff245e0f5eb5a25832df811e8df9dd100d30c2c14d821) // n_inv
                mstore(0x0620, 0x1283ba6f4b7b1a76ba2008fe823128bea4adb9269cbfd7c41c223be65bc60863) // omega
                mstore(0x0640, 0x1589862c1cf3f8b59954774980cc9361c568bcabd9cb7d0858de685794d4772b) // omega_inv
                mstore(0x0660, 0x2fffa2b50d66f628412d9782f09d3386d766a1168304babe2165fe7ec962e65b) // omega_inv_to_l
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
                mstore(0x0840, 0x2b620e9833aabbacbd78ec84f726b7139732a51f815714245d173fd60e88923f) // fixed_comms[0].x
                mstore(0x0860, 0x297e4c47f8a8d2912e43d0a9ef64403336f431e49c5be14cb5033681d1383221) // fixed_comms[0].y
                mstore(0x0880, 0x1a3b19212fe7f935120e6aae1f97d10a20120a52da0a67ce16af9d188c0d6e3b) // fixed_comms[1].x
                mstore(0x08a0, 0x2ac8b11da5e4faa2a579ff031952bd69a1e13c66ac0643ab0ff067810364ff41) // fixed_comms[1].y
                mstore(0x08c0, 0x14a96af320b776e442535ed47db71b66614b2674bd39b403f3ab9bb027923553) // fixed_comms[2].x
                mstore(0x08e0, 0x26125c5a73e00bb996f092ea128f3630baa6c7bc66efbe35cbceb4fb437ace6a) // fixed_comms[2].y
                mstore(0x0900, 0x1c5138c9c6b1b308b1afaf10458d313ce58b001405dd02c57cdfe94ec079bd4c) // fixed_comms[3].x
                mstore(0x0920, 0x0f9e2de627511aead63083210857b1f2df298ecdd1ab72feaf35963031b547bb) // fixed_comms[3].y
                mstore(0x0940, 0x08e11fa534b51d67a1fd9e092112d007a3a24fca0890a68be0a4248c708cd85d) // fixed_comms[4].x
                mstore(0x0960, 0x1d655405defeacf3309cbb143ca07c71dbe6fb5b67dbe29d89e4ae81c09c979b) // fixed_comms[4].y
                mstore(0x0980, 0x046923e7355663db74257a5755961f3309e47d9ab60417cf2cff29c44c2db94b) // fixed_comms[5].x
                mstore(0x09a0, 0x0bfc2b82b291ffa4831b25a0089f18832b7b9cf46a10971f03aa3a13342fa1e8) // fixed_comms[5].y
                mstore(0x09c0, 0x046923e7355663db74257a5755961f3309e47d9ab60417cf2cff29c44c2db94b) // fixed_comms[6].x
                mstore(0x09e0, 0x0bfc2b82b291ffa4831b25a0089f18832b7b9cf46a10971f03aa3a13342fa1e8) // fixed_comms[6].y
                mstore(0x0a00, 0x08412d0161385f9b5c2054b5b93b8fc41790b8527826c7e0522e50f91680b034) // fixed_comms[7].x
                mstore(0x0a20, 0x0993c0109e658ce6c051d1862fa8f635675911c2d249dafb3ca82f85b1fb71e5) // fixed_comms[7].y
                mstore(0x0a40, 0x08412d0161385f9b5c2054b5b93b8fc41790b8527826c7e0522e50f91680b034) // fixed_comms[8].x
                mstore(0x0a60, 0x0993c0109e658ce6c051d1862fa8f635675911c2d249dafb3ca82f85b1fb71e5) // fixed_comms[8].y
                mstore(0x0a80, 0x0fac457b2d6adf59b951df6f72fd88d421c519d6b5ae788ed48a17992a97914e) // fixed_comms[9].x
                mstore(0x0aa0, 0x294367bbb1189f2019d518973609548a613df3d4dbf61860eb626330635f37e9) // fixed_comms[9].y
                mstore(0x0ac0, 0x0fac457b2d6adf59b951df6f72fd88d421c519d6b5ae788ed48a17992a97914e) // fixed_comms[10].x
                mstore(0x0ae0, 0x294367bbb1189f2019d518973609548a613df3d4dbf61860eb626330635f37e9) // fixed_comms[10].y
                mstore(0x0b00, 0x071b6e89fcb794897ab47101d2e9e214ed4f5a0fc5e8086f326cbfd31e01a192) // fixed_comms[11].x
                mstore(0x0b20, 0x1846fdd45dc7bbfd8a5be4cd4fd7d63add18a9396486a082e42847a61c8941bb) // fixed_comms[11].y
                mstore(0x0b40, 0x1caf3952401aefd7402ff8b444ef4f2294d7c8aefc7346ee5345d25ecd025a7d) // fixed_comms[12].x
                mstore(0x0b60, 0x0b15abfd4a2c991a892b795f86f34e59d7ec3b5b58d960fa26d17eef0ab97285) // fixed_comms[12].y
                mstore(0x0b80, 0x1caf3952401aefd7402ff8b444ef4f2294d7c8aefc7346ee5345d25ecd025a7d) // fixed_comms[13].x
                mstore(0x0ba0, 0x0b15abfd4a2c991a892b795f86f34e59d7ec3b5b58d960fa26d17eef0ab97285) // fixed_comms[13].y
                mstore(0x0bc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].x
                mstore(0x0be0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[14].y
                mstore(0x0c00, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[15].x
                mstore(0x0c20, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[15].y
                mstore(0x0c40, 0x0a8c8d97221a53a70526b3dcbeff5be4e657d3b926081079e28d623a17c5f3ef) // fixed_comms[16].x
                mstore(0x0c60, 0x0173edbb1327c11966b9a28d3dbb772526c3ac7adf30b0d455743260d2da91c2) // fixed_comms[16].y
                mstore(0x0c80, 0x16833492f044fa5522d06b34777a9de75dcb0dd4391907e224454b997d4c5307) // fixed_comms[17].x
                mstore(0x0ca0, 0x2175816ff9a101054fc1e999304d60f9e35717917f2dd224bc0ac6935574b0e1) // fixed_comms[17].y
                mstore(0x0cc0, 0x1961b94724f3f2517316f788670843ac3887462a204029647f06863b50c7c57e) // fixed_comms[18].x
                mstore(0x0ce0, 0x2eca13aaafd5c7d330c1d21bb8b4dcccfa2a5c08ac92958a6dd4f7667cbc6d9d) // fixed_comms[18].y
                mstore(0x0d00, 0x0b25ebcd6b00afdfde73fa921ce92f8e374b2c7c93e8c6c7bee1ee2f061cb555) // fixed_comms[19].x
                mstore(0x0d20, 0x10a8dbf39ae303a448a9f70a0d74536930e77b1de262ac74516bd68c4267d19c) // fixed_comms[19].y
                mstore(0x0d40, 0x27c47e8b7f8ec811779be2e3d11b7c261895e01c1ba7eb92f7a172eff2d0468d) // fixed_comms[20].x
                mstore(0x0d60, 0x12547172a36f1204ff290901cd7e92fc198bee804d856a328cd2e47edf2eeb01) // fixed_comms[20].y
                mstore(0x0d80, 0x1c4e13c8ffdaf4824187bb05e7ccf5f88732a3098b702994f00e58bfa333b9c2) // fixed_comms[21].x
                mstore(0x0da0, 0x3056b82bd3bbb3d4a57ccbadfb741dcb563ebab193a7c07e98171a1176323d3e) // fixed_comms[21].y
                mstore(0x0dc0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[22].x
                mstore(0x0de0, 0x0000000000000000000000000000000000000000000000000000000000000000) // fixed_comms[22].y
                mstore(0x0e00, 0x1b294a895a11bf5796b6e9891748a3a4564516b8078deb9ea8a7cfd9740c4f26) // permutation_comms[0].x
                mstore(0x0e20, 0x0964dd2c7a557df99ae9645927145e61dee234361a53fc6e436262fbf3d6ec0e) // permutation_comms[0].y
                mstore(0x0e40, 0x03816f9a47b97717fd7e4959affdd295bd15d483864586e7732fb92597e1dc59) // permutation_comms[1].x
                mstore(0x0e60, 0x16e462e91fdbbd304381d9c4f9291deabc533b157ac6791061914c5b9f7cbcc5) // permutation_comms[1].y
                mstore(0x0e80, 0x0c5fe702825db500c2eca6a648567e7607dd7bde10be263157098db93083ee1e) // permutation_comms[2].x
                mstore(0x0ea0, 0x2a32e8bb9158c71184e3370babfb17ae55830abdfe879d91ea83688b5cf2a8a6) // permutation_comms[2].y
                mstore(0x0ec0, 0x2348711cc4f00d0580070456a87eaab2a3ae634efbbc8a7804d2378b86980654) // permutation_comms[3].x
                mstore(0x0ee0, 0x1192b8c1b5c461227eba34ba9cbe25c22a16d99c78032794f6d97b996c5f9b4b) // permutation_comms[3].y
                mstore(0x0f00, 0x0b2b002cbb1c4135accb1bafda5c3ea4168dc183a11748397686f8e2cf399b09) // permutation_comms[4].x
                mstore(0x0f20, 0x166e90ee3cad5f2dff40f4319b6ce31709e8ebd69dc90037f363c5fdad93cdc3) // permutation_comms[4].y
                mstore(0x0f40, 0x1da26db5bfdbb11c847b5077704b8c7a9909b914a6e19b546209316a1046bfde) // permutation_comms[5].x
                mstore(0x0f60, 0x12d2a95d2872f11f80f23f143e1a39154ae7ff280555139ca9d66ca04ce65004) // permutation_comms[5].y
                mstore(0x0f80, 0x082263d59ec8a692a9d87470a37d6d46488e6d070f311cf93b4ac0abfafc7bf0) // permutation_comms[6].x
                mstore(0x0fa0, 0x1b0c20aff862dbf53cb066a963a053ba46d1c7e7e990502cc1e789cdcfa70faa) // permutation_comms[6].y
                mstore(0x0fc0, 0x0333b0c3ea0767a7aa88c40167c59ed9b387375ecb9d6015150b5c8921b1be69) // permutation_comms[7].x
                mstore(0x0fe0, 0x27f4a104c90ec3f3949730148f5e938bdb0bf8e48b8fb45cd2c9a79d6f5d786e) // permutation_comms[7].y
                mstore(0x1000, 0x25ee56e909c4b42ed663380b473ae4535ff33d3c8173260ff694f9a13a4de4b1) // permutation_comms[8].x
                mstore(0x1020, 0x0d749da3ec10fe8b9d3a5db303df5187048ed996845088ce935185bbfad1bc56) // permutation_comms[8].y
                mstore(0x1040, 0x2fdfcab3e40d3b14db87bea6f5e015d1e1ebc16bee260137eb437778f97d5fbe) // permutation_comms[9].x
                mstore(0x1060, 0x15f1b9378d463a380c2bf7b52c7f4bed9ac83f3a412502e21c70ea549106f8c4) // permutation_comms[9].y
                mstore(0x1080, 0x2e308a99d29b19fa65dde121db22e32e7d2ca14855c193848173ce36f4f86e38) // permutation_comms[10].x
                mstore(0x10a0, 0x1161eafc7788178d7ca16d156c58d667cf3d66b79931624c0b76e7fa66e5c87f) // permutation_comms[10].y
                mstore(0x10c0, 0x2ce8fbc8d2853d66920e8f1fe80d39fad36acc2e666d79f5c862af14d7963fcd) // permutation_comms[11].x
                mstore(0x10e0, 0x2c1aa797ea9374bb18723bbe67049132474afead60faf2091165178e692aef10) // permutation_comms[11].y
                mstore(0x1100, 0x144c9319cdd5345d524b535480109d81d962ed21bd0a85d8d2bf569b5479ac8f) // permutation_comms[12].x
                mstore(0x1120, 0x2163f4e28c6d7a3a9b11925001cf6c93b39ae62d7f9b4b1bf40a1d2cba3bccd2) // permutation_comms[12].y
                mstore(0x1140, 0x23f756809eb2f2d197bd6c016c55eb0905566bf23846de575bcb4baea4c1559f) // permutation_comms[13].x
                mstore(0x1160, 0x0ec64d610d43ab66d49a30fc7ee97f5cadb4d79a219c8d784171a981726c5e14) // permutation_comms[13].y
                mstore(0x1180, 0x22e8fc6a727747341acc072240360206b3dd3abad75763b9e49ee7f727f7a8da) // permutation_comms[14].x
                mstore(0x11a0, 0x123d8ce039bf98bc3655306b41556d3de852805b4122faba82550d33c27adf58) // permutation_comms[14].y
                mstore(0x11c0, 0x022c33533e5a1b9172c1dbd9f344cca443a63be2d7ddbc753308f38958c72c1b) // permutation_comms[15].x
                mstore(0x11e0, 0x08a60d0b00b424f5229b429866e74dc4005238259d26692ee8e9b1366e01936d) // permutation_comms[15].y
                mstore(0x1200, 0x1b0b57337c68658c8f96053e0891421495c8b38314d98d45454ddec7963fa31a) // permutation_comms[16].x
                mstore(0x1220, 0x119ea5ad4e7142b246e8aa41720b2347b1c4e05d51b437f92031172afd14c512) // permutation_comms[16].y

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
                    let f_16 := calldataload(0x1104)
                    let var0 := 0x2
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let a_0 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0d64)
                    let var10 := addmod(a_0, a_4, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_8, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := var13
                }
                {
                    let f_17 := calldataload(0x1124)
                    let var0 := 0x2
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_9 := calldataload(0x0e04)
                    let a_1 := calldataload(0x0d04)
                    let a_5 := calldataload(0x0d84)
                    let var10 := addmod(a_1, a_5, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_9, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_18 := calldataload(0x1144)
                    let var0 := 0x2
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_10 := calldataload(0x0e24)
                    let a_2 := calldataload(0x0d24)
                    let a_6 := calldataload(0x0da4)
                    let var10 := addmod(a_2, a_6, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_10, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_19 := calldataload(0x1164)
                    let var0 := 0x2
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_11 := calldataload(0x0e44)
                    let a_3 := calldataload(0x0d44)
                    let a_7 := calldataload(0x0dc4)
                    let var10 := addmod(a_3, a_7, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_11, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_16 := calldataload(0x1104)
                    let var0 := 0x1
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let a_0 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0d64)
                    let var10 := mulmod(a_0, a_4, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_8, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_17 := calldataload(0x1124)
                    let var0 := 0x1
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_9 := calldataload(0x0e04)
                    let a_1 := calldataload(0x0d04)
                    let a_5 := calldataload(0x0d84)
                    let var10 := mulmod(a_1, a_5, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_9, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_18 := calldataload(0x1144)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_10 := calldataload(0x0e24)
                    let a_2 := calldataload(0x0d24)
                    let a_6 := calldataload(0x0da4)
                    let var10 := mulmod(a_2, a_6, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_10, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_19 := calldataload(0x1164)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_11 := calldataload(0x0e44)
                    let a_3 := calldataload(0x0d44)
                    let a_7 := calldataload(0x0dc4)
                    let var10 := mulmod(a_3, a_7, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_11, var11, R)
                    let var13 := mulmod(var9, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_16 := calldataload(0x1104)
                    let var0 := 0x1
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let a_0 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0d64)
                    let var10 := sub(R, a_4)
                    let var11 := addmod(a_0, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_8, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_17 := calldataload(0x1124)
                    let var0 := 0x1
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_9 := calldataload(0x0e04)
                    let a_1 := calldataload(0x0d04)
                    let a_5 := calldataload(0x0d84)
                    let var10 := sub(R, a_5)
                    let var11 := addmod(a_1, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_9, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_18 := calldataload(0x1144)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_10 := calldataload(0x0e24)
                    let a_2 := calldataload(0x0d24)
                    let a_6 := calldataload(0x0da4)
                    let var10 := sub(R, a_6)
                    let var11 := addmod(a_2, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_10, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_19 := calldataload(0x1164)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x4
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_11 := calldataload(0x0e44)
                    let a_3 := calldataload(0x0d44)
                    let a_7 := calldataload(0x0dc4)
                    let var10 := sub(R, a_7)
                    let var11 := addmod(a_3, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_11, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_17 := calldataload(0x1124)
                    let var0 := 0x1
                    let var1 := sub(R, f_17)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_17, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let a_8_prev_1 := calldataload(0x0ec4)
                    let var10 := 0x0
                    let a_0 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0d64)
                    let var11 := mulmod(a_0, a_4, R)
                    let var12 := addmod(var10, var11, R)
                    let a_1 := calldataload(0x0d04)
                    let a_5 := calldataload(0x0d84)
                    let var13 := mulmod(a_1, a_5, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := addmod(a_8_prev_1, var14, R)
                    let var16 := sub(R, var15)
                    let var17 := addmod(a_8, var16, R)
                    let var18 := mulmod(var9, var17, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var18, r)
                }
                {
                    let f_21 := calldataload(0x11a4)
                    let var0 := 0x2
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0e24)
                    let a_10_prev_1 := calldataload(0x0ee4)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0d24)
                    let a_6 := calldataload(0x0da4)
                    let var8 := mulmod(a_2, a_6, R)
                    let var9 := addmod(var7, var8, R)
                    let a_3 := calldataload(0x0d44)
                    let a_7 := calldataload(0x0dc4)
                    let var10 := mulmod(a_3, a_7, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := addmod(a_10_prev_1, var11, R)
                    let var13 := sub(R, var12)
                    let var14 := addmod(a_10, var13, R)
                    let var15 := mulmod(var6, var14, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var15, r)
                }
                {
                    let f_16 := calldataload(0x1104)
                    let var0 := 0x1
                    let var1 := sub(R, f_16)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_16, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let var10 := 0x0
                    let a_0 := calldataload(0x0ce4)
                    let a_4 := calldataload(0x0d64)
                    let var11 := mulmod(a_0, a_4, R)
                    let var12 := addmod(var10, var11, R)
                    let a_1 := calldataload(0x0d04)
                    let a_5 := calldataload(0x0d84)
                    let var13 := mulmod(a_1, a_5, R)
                    let var14 := addmod(var12, var13, R)
                    let var15 := sub(R, var14)
                    let var16 := addmod(a_8, var15, R)
                    let var17 := mulmod(var9, var16, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var17, r)
                }
                {
                    let f_20 := calldataload(0x1184)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0e24)
                    let var7 := 0x0
                    let a_2 := calldataload(0x0d24)
                    let a_6 := calldataload(0x0da4)
                    let var8 := mulmod(a_2, a_6, R)
                    let var9 := addmod(var7, var8, R)
                    let a_3 := calldataload(0x0d44)
                    let a_7 := calldataload(0x0dc4)
                    let var10 := mulmod(a_3, a_7, R)
                    let var11 := addmod(var9, var10, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_10, var12, R)
                    let var14 := mulmod(var6, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_18 := calldataload(0x1144)
                    let var0 := 0x1
                    let var1 := sub(R, f_18)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_18, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let a_4 := calldataload(0x0d64)
                    let var10 := mulmod(var0, a_4, R)
                    let a_5 := calldataload(0x0d84)
                    let var11 := mulmod(var10, a_5, R)
                    let var12 := sub(R, var11)
                    let var13 := addmod(a_8, var12, R)
                    let var14 := mulmod(var9, var13, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var14, r)
                }
                {
                    let f_21 := calldataload(0x11a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0e24)
                    let a_6 := calldataload(0x0da4)
                    let var7 := mulmod(var0, a_6, R)
                    let a_7 := calldataload(0x0dc4)
                    let var8 := mulmod(var7, a_7, R)
                    let var9 := sub(R, var8)
                    let var10 := addmod(a_10, var9, R)
                    let var11 := mulmod(var6, var10, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var11, r)
                }
                {
                    let f_20 := calldataload(0x1184)
                    let var0 := 0x2
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0de4)
                    let a_8_prev_1 := calldataload(0x0ec4)
                    let var7 := 0x1
                    let a_4 := calldataload(0x0d64)
                    let var8 := mulmod(var7, a_4, R)
                    let a_5 := calldataload(0x0d84)
                    let var9 := mulmod(var8, a_5, R)
                    let var10 := mulmod(a_8_prev_1, var9, R)
                    let var11 := sub(R, var10)
                    let var12 := addmod(a_8, var11, R)
                    let var13 := mulmod(var6, var12, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var13, r)
                }
                {
                    let f_21 := calldataload(0x11a4)
                    let var0 := 0x1
                    let var1 := sub(R, f_21)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_21, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_10 := calldataload(0x0e24)
                    let a_10_prev_1 := calldataload(0x0ee4)
                    let a_6 := calldataload(0x0da4)
                    let var7 := mulmod(var0, a_6, R)
                    let a_7 := calldataload(0x0dc4)
                    let var8 := mulmod(var7, a_7, R)
                    let var9 := mulmod(a_10_prev_1, var8, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_10, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_20 := calldataload(0x1184)
                    let var0 := 0x1
                    let var1 := sub(R, f_20)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_20, var2, R)
                    let var4 := 0x3
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let a_8 := calldataload(0x0de4)
                    let var7 := 0x0
                    let a_4 := calldataload(0x0d64)
                    let var8 := addmod(var7, a_4, R)
                    let a_5 := calldataload(0x0d84)
                    let var9 := addmod(var8, a_5, R)
                    let var10 := sub(R, var9)
                    let var11 := addmod(a_8, var10, R)
                    let var12 := mulmod(var6, var11, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var12, r)
                }
                {
                    let f_22 := calldataload(0x11c4)
                    let var0 := 0x1
                    let var1 := sub(R, f_22)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_22, var2, R)
                    let a_10 := calldataload(0x0e24)
                    let var4 := 0x0
                    let a_6 := calldataload(0x0da4)
                    let var5 := addmod(var4, a_6, R)
                    let a_7 := calldataload(0x0dc4)
                    let var6 := addmod(var5, a_7, R)
                    let var7 := sub(R, var6)
                    let var8 := addmod(a_10, var7, R)
                    let var9 := mulmod(var3, var8, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var9, r)
                }
                {
                    let f_19 := calldataload(0x1164)
                    let var0 := 0x1
                    let var1 := sub(R, f_19)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_19, var2, R)
                    let var4 := 0x2
                    let var5 := addmod(var4, var1, R)
                    let var6 := mulmod(var3, var5, R)
                    let var7 := 0x3
                    let var8 := addmod(var7, var1, R)
                    let var9 := mulmod(var6, var8, R)
                    let a_8 := calldataload(0x0de4)
                    let a_8_prev_1 := calldataload(0x0ec4)
                    let var10 := 0x0
                    let a_4 := calldataload(0x0d64)
                    let var11 := addmod(var10, a_4, R)
                    let a_5 := calldataload(0x0d84)
                    let var12 := addmod(var11, a_5, R)
                    let var13 := addmod(a_8_prev_1, var12, R)
                    let var14 := sub(R, var13)
                    let var15 := addmod(a_8, var14, R)
                    let var16 := mulmod(var9, var15, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var16, r)
                }
                {
                    let f_22 := calldataload(0x11c4)
                    let var0 := 0x2
                    let var1 := sub(R, f_22)
                    let var2 := addmod(var0, var1, R)
                    let var3 := mulmod(f_22, var2, R)
                    let a_10 := calldataload(0x0e24)
                    let a_10_prev_1 := calldataload(0x0ee4)
                    let var4 := 0x0
                    let a_6 := calldataload(0x0da4)
                    let var5 := addmod(var4, a_6, R)
                    let a_7 := calldataload(0x0dc4)
                    let var6 := addmod(var5, a_7, R)
                    let var7 := addmod(a_10_prev_1, var6, R)
                    let var8 := sub(R, var7)
                    let var9 := addmod(a_10, var8, R)
                    let var10 := mulmod(var3, var9, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var10, r)
                }
                {
                    let f_3 := calldataload(0x0f64)
                    let var0 := 0x0
                    let var1 := mulmod(f_3, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_4 := calldataload(0x0f84)
                    let var0 := 0x0
                    let var1 := mulmod(f_4, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_5 := calldataload(0x0fa4)
                    let var0 := 0x0
                    let var1 := mulmod(f_5, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_6 := calldataload(0x0fc4)
                    let var0 := 0x0
                    let var1 := mulmod(f_6, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_7 := calldataload(0x0fe4)
                    let var0 := 0x0
                    let var1 := mulmod(f_7, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_8 := calldataload(0x1004)
                    let var0 := 0x0
                    let var1 := mulmod(f_8, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_9 := calldataload(0x1024)
                    let var0 := 0x0
                    let var1 := mulmod(f_9, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let f_10 := calldataload(0x1044)
                    let var0 := 0x0
                    let var1 := mulmod(f_10, var0, R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), var1, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(R, mulmod(l_0, calldataload(0x1424), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x15a4)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, R), sub(R, perm_z_last), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1484), sub(R, calldataload(0x1464)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x14e4), sub(R, calldataload(0x14c4)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x1544), sub(R, calldataload(0x1524)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x15a4), sub(R, calldataload(0x1584)), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1444)
                    let rhs := calldataload(0x1424)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ce4), mulmod(beta, calldataload(0x1204), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d04), mulmod(beta, calldataload(0x1224), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d24), mulmod(beta, calldataload(0x1244), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d44), mulmod(beta, calldataload(0x1264), R), R), gamma, R), R)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ce4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
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
                    let lhs := calldataload(0x14a4)
                    let rhs := calldataload(0x1484)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d64), mulmod(beta, calldataload(0x1284), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0d84), mulmod(beta, calldataload(0x12a4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0da4), mulmod(beta, calldataload(0x12c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0dc4), mulmod(beta, calldataload(0x12e4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0d64), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0d84), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0da4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0dc4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1504)
                    let rhs := calldataload(0x14e4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0de4), mulmod(beta, calldataload(0x1304), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0e04), mulmod(beta, calldataload(0x1324), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0e24), mulmod(beta, calldataload(0x1344), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0e44), mulmod(beta, calldataload(0x1364), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0de4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0e04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0e24), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0e44), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x1564)
                    let rhs := calldataload(0x1544)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0e64), mulmod(beta, calldataload(0x1384), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0e84), mulmod(beta, calldataload(0x13a4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0ea4), mulmod(beta, calldataload(0x13c4), R), R), gamma, R), R)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0f04), mulmod(beta, calldataload(0x13e4), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0e64), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0e84), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0ea4), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0f04), mload(0x00), R), gamma, R), R)
                    mstore(0x00, mulmod(mload(0x00), DELTA, R))
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x15c4)
                    let rhs := calldataload(0x15a4)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x1404), R), R), gamma, R), R)
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), R), gamma, R), R)
                    let left_sub_right := addmod(lhs, sub(R, rhs), R)
                    let eval := addmod(left_sub_right, sub(R, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), R), R)), R)
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
                        let var0 := 0x1
                        let f_11 := calldataload(0x1064)
                        let var1 := mulmod(var0, f_11, R)
                        let a_12 := calldataload(0x0e64)
                        let var2 := mulmod(a_12, f_11, R)
                        let a_13 := calldataload(0x0e84)
                        let var3 := mulmod(a_13, f_11, R)
                        let a_14 := calldataload(0x0ea4)
                        let var4 := mulmod(a_14, f_11, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_12 := calldataload(0x1084)
                        let var1 := mulmod(var0, f_12, R)
                        let a_0 := calldataload(0x0ce4)
                        let var2 := mulmod(a_0, f_12, R)
                        let a_4 := calldataload(0x0d64)
                        let var3 := mulmod(a_4, f_12, R)
                        let a_8 := calldataload(0x0de4)
                        let var4 := mulmod(a_8, f_12, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
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
                        let var0 := 0x1
                        let f_11 := calldataload(0x1064)
                        let var1 := mulmod(var0, f_11, R)
                        let a_12 := calldataload(0x0e64)
                        let var2 := mulmod(a_12, f_11, R)
                        let a_13 := calldataload(0x0e84)
                        let var3 := mulmod(a_13, f_11, R)
                        let a_14 := calldataload(0x0ea4)
                        let var4 := mulmod(a_14, f_11, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_13 := calldataload(0x10a4)
                        let var1 := mulmod(var0, f_13, R)
                        let a_1 := calldataload(0x0d04)
                        let var2 := mulmod(a_1, f_13, R)
                        let a_5 := calldataload(0x0d84)
                        let var3 := mulmod(a_5, f_13, R)
                        let a_9 := calldataload(0x0e04)
                        let var4 := mulmod(a_9, f_13, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
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
                        let var0 := 0x1
                        let f_11 := calldataload(0x1064)
                        let var1 := mulmod(var0, f_11, R)
                        let a_12 := calldataload(0x0e64)
                        let var2 := mulmod(a_12, f_11, R)
                        let a_13 := calldataload(0x0e84)
                        let var3 := mulmod(a_13, f_11, R)
                        let a_14 := calldataload(0x0ea4)
                        let var4 := mulmod(a_14, f_11, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_14 := calldataload(0x10c4)
                        let var1 := mulmod(var0, f_14, R)
                        let a_2 := calldataload(0x0d24)
                        let var2 := mulmod(a_2, f_14, R)
                        let a_6 := calldataload(0x0da4)
                        let var3 := mulmod(a_6, f_14, R)
                        let a_10 := calldataload(0x0e24)
                        let var4 := mulmod(a_10, f_14, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
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
                        let var0 := 0x1
                        let f_11 := calldataload(0x1064)
                        let var1 := mulmod(var0, f_11, R)
                        let a_12 := calldataload(0x0e64)
                        let var2 := mulmod(a_12, f_11, R)
                        let a_13 := calldataload(0x0e84)
                        let var3 := mulmod(a_13, f_11, R)
                        let a_14 := calldataload(0x0ea4)
                        let var4 := mulmod(a_14, f_11, R)
                        table := var1
                        table := addmod(mulmod(table, theta, R), var2, R)
                        table := addmod(mulmod(table, theta, R), var3, R)
                        table := addmod(mulmod(table, theta, R), var4, R)
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let var0 := 0x1
                        let f_15 := calldataload(0x10e4)
                        let var1 := mulmod(var0, f_15, R)
                        let a_3 := calldataload(0x0d44)
                        let var2 := mulmod(a_3, f_15, R)
                        let a_7 := calldataload(0x0dc4)
                        let var3 := mulmod(a_7, f_15, R)
                        let a_11 := calldataload(0x0e44)
                        let var4 := mulmod(a_11, f_15, R)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, R), var2, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var3, R)
                        input_0 := addmod(mulmod(input_0, theta, R), var4, R)
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
                        let f_1 := calldataload(0x0f24)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_3 := calldataload(0x0f64)
                        let var0 := 0x1
                        let var1 := mulmod(f_3, var0, R)
                        let a_0 := calldataload(0x0ce4)
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
                        let f_1 := calldataload(0x0f24)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_4 := calldataload(0x0f84)
                        let var0 := 0x1
                        let var1 := mulmod(f_4, var0, R)
                        let a_1 := calldataload(0x0d04)
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
                        let f_1 := calldataload(0x0f24)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_5 := calldataload(0x0fa4)
                        let var0 := 0x1
                        let var1 := mulmod(f_5, var0, R)
                        let a_2 := calldataload(0x0d24)
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
                        let f_1 := calldataload(0x0f24)
                        table := f_1
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_6 := calldataload(0x0fc4)
                        let var0 := 0x1
                        let var1 := mulmod(f_6, var0, R)
                        let a_3 := calldataload(0x0d44)
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
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x18c4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x18a4), sub(R, calldataload(0x1884)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x18e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x18e4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0f44)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_7 := calldataload(0x0fe4)
                        let var0 := 0x1
                        let var1 := mulmod(f_7, var0, R)
                        let a_0 := calldataload(0x0ce4)
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
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1924), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1904), sub(R, calldataload(0x18e4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1944), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1944), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0f44)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_8 := calldataload(0x1004)
                        let var0 := 0x1
                        let var1 := mulmod(f_8, var0, R)
                        let a_1 := calldataload(0x0d04)
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
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1984), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1964), sub(R, calldataload(0x1944)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x19a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x19a4), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0f44)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_9 := calldataload(0x1024)
                        let var0 := 0x1
                        let var1 := mulmod(f_9, var0, R)
                        let a_2 := calldataload(0x0d24)
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
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x19e4), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x19c4), sub(R, calldataload(0x19a4)), R), R)
                    }
                    let eval := mulmod(addmod(1, sub(R, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), R)), R), addmod(lhs, sub(R, rhs), R), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x1a04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x1a04), R)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_2 := calldataload(0x0f44)
                        table := f_2
                        table := addmod(table, beta, R)
                    }
                    let input_0
                    {
                        let f_10 := calldataload(0x1044)
                        let var0 := 0x1
                        let var1 := mulmod(f_10, var0, R)
                        let a_3 := calldataload(0x0d44)
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
                        rhs := addmod(rhs, sub(R, mulmod(calldataload(0x1a44), tmp, R)), R)
                        lhs := mulmod(mulmod(table, tmp, R), addmod(calldataload(0x1a24), sub(R, calldataload(0x1a04)), R), R)
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
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x11e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), R), R)
                    for
                        {
                            let mptr := 0x1404
                            let mptr_end := 0x11e4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    for
                        {
                            let mptr := 0x11c4
                            let mptr_end := 0x0ee4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1a44), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x19e4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1984), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x1924), R), R)
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
                    for
                        {
                            let mptr := 0x0ea4
                            let mptr_end := 0x0e24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, R), mulmod(coeff, calldataload(mptr), R), R)
                    }
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0e04), R), R)
                    for
                        {
                            let mptr := 0x0dc4
                            let mptr_end := 0x0cc4
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
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0ee4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0e24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0ec4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0de4), R), R)
                    r_eval := mulmod(r_eval, mload(0x0440), R)
                    mstore(0x04c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1584), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1544), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1564), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1524), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x14e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1504), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x14c4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1484), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x14a4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x1464), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x1424), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x1444), R), R)
                    r_eval := mulmod(r_eval, mload(0x0460), R)
                    mstore(0x04e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1a04), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1a24), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x19a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x19c4), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x1944), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1964), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x18e4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x1904), R), R)
                    r_eval := mulmod(r_eval, zeta, R)
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
                    r_eval := addmod(r_eval, mulmod(mload(0xe0), calldataload(0x15a4), R), R)
                    r_eval := addmod(r_eval, mulmod(mload(0x0100), calldataload(0x15c4), R), R)
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
                    mstore(0x00, calldataload(0x0b64))
                    mstore(0x20, calldataload(0x0b84))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x1200
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
                            let mptr := 0x06e4
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
                    mstore(0x80, calldataload(0x07e4))
                    mstore(0xa0, calldataload(0x0804))
                    for
                        {
                            let mptr := 0x07a4
                            let mptr_end := 0x06e4
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
                    mstore(0x80, calldataload(0x0b24))
                    mstore(0xa0, calldataload(0x0b44))
                    for
                        {
                            let mptr := 0x0ae4
                            let mptr_end := 0x07e4
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
                    mstore(0x80, calldataload(0x1a64))
                    mstore(0xa0, calldataload(0x1a84))
                    success := ec_mul_tmp(success, sub(R, mload(0x0400)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x1aa4))
                    mstore(0xa0, calldataload(0x1ac4))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x1aa4))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x1ac4))
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