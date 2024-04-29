// This file is part of Darwinia.
// Copyright (C) 2018-2022 Darwinia Network
// SPDX-License-Identifier: GPL-3.0
//
// Darwinia is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Darwinia is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Darwinia. If not, see <https://www.gnu.org/licenses/>.

pragma solidity ^0.8.17;

import "../src/bls12381/BLS.sol";
import "../src/util/Bytes.sol";

contract BLSTest {
    using Bytes for bytes;

    function expand_message_xmd(bytes memory message) public pure returns (bytes memory) {
        return BLS12FP2.expand_message_xmd(message);
    }

    function hash_to_field_fq2(bytes memory message) public view returns (Bls12Fp2[2] memory result) {
        return BLS12FP2.hash_to_field(message);
    }

    function map_to_curve_g2(Bls12Fp2 memory f) public view returns (Bls12G2 memory) {
        return BLS12G2Affine.map_to_curve(f);
    }

    function hash_to_curve_g2(bytes memory message) public view returns (Bls12G2 memory) {
        return BLS12G2Affine.hash_to_curve(message);
    }

    function bls_pairing_check(Bls12G1 memory pk, Bls12G2 memory h, Bls12G2 memory s) public view returns (bool) {
        return BLS.verify(pk, h, s);
    }

    function deserialize_g1(bytes memory g1) public pure returns (Bls12G1 memory) {
        return BLS12G1Affine.deserialize(g1);
    }

    function serialize_g1(Bls12G1 memory g1) public pure returns (bytes memory) {
        return BLS12G1Affine.serialize(g1);
    }

    function deserialize_g2(bytes memory g2) public pure returns (Bls12G2 memory) {
        return BLS12G2Affine.deserialize(g2);
    }

    function serialize_g2(Bls12G2 memory g2) public pure returns (bytes memory) {
        return BLS12G2Affine.serialize(g2);
    }

    function aggregate_pks(bytes[] calldata pubkeys) public view returns (Bls12G1 memory) {
        return BLS.aggregate(pubkeys);
    }

    function fast_aggregate_verify(
        bytes[] calldata uncompressed_pubkeys,
        bytes memory message,
        bytes calldata uncompressed_signature
    )
        public
        view
        returns (bool)
    {
        return BLS.fast_aggregate_verify(uncompressed_pubkeys, message, uncompressed_signature);
    }

    function encode_g1(Bls12G1 memory p) public pure returns (bytes memory) {
        return abi.encodePacked(p.x.a, p.x.b, p.y.a, p.y.b);
    }

    function decode_g1(bytes memory x) public pure returns (Bls12G1 memory) {
        return Bls12G1(
            Bls12Fp(x.slice_to_uint(0, 32), x.slice_to_uint(32, 64)),
            Bls12Fp(x.slice_to_uint(64, 96), x.slice_to_uint(96, 128))
        );
    }

    function add_g1(bytes memory input) public view returns (bytes memory) {
        Bls12G1 memory p0 = decode_g1(input.substr(0, 128));
        Bls12G1 memory p1 = decode_g1(input.substr(128, 128));
        Bls12G1 memory q = BLS12G1Affine.add(p0, p1);
        return encode_g1(q);
    }

    function encode_g2(Bls12G2 memory p) public pure returns (bytes memory) {
        return abi.encodePacked(p.x.c0.a, p.x.c0.b, p.x.c1.a, p.x.c1.b, p.y.c0.a, p.y.c0.b, p.y.c1.a, p.y.c1.b);
    }

    function decode_g2(bytes memory x) public pure returns (Bls12G2 memory) {
        return Bls12G2(
            Bls12Fp2(
                Bls12Fp(x.slice_to_uint(0, 32), x.slice_to_uint(32, 64)),
                Bls12Fp(x.slice_to_uint(64, 96), x.slice_to_uint(96, 128))
            ),
            Bls12Fp2(
                Bls12Fp(x.slice_to_uint(128, 160), x.slice_to_uint(160, 192)),
                Bls12Fp(x.slice_to_uint(192, 224), x.slice_to_uint(224, 256))
            )
        );
    }

    function add_g2(bytes memory input) public view returns (bytes memory) {
        Bls12G2 memory p0 = decode_g2(input.substr(0, 256));
        Bls12G2 memory p1 = decode_g2(input.substr(256, 256));
        Bls12G2 memory q = BLS12G2Affine.add(p0, p1);
        return encode_g2(q);
    }

    // function mul_g2(bytes memory input) public view returns (bytes memory) {
    //     Bls12G2 memory p0 = decode_g2(input.substr(0, 256));
    //     uint scalar = input.slice_to_uint(256, 288);
    //     Bls12G2 memory q = BLS12G2Affine.mul(p0, scalar);
    //     return encode_g2(q);
    // }

    function map_to_curve_g2(bytes memory input) public view returns (bytes memory) {
        Bls12Fp2 memory f = Bls12Fp2(
            Bls12Fp(input.slice_to_uint(0, 32), input.slice_to_uint(32, 64)),
            Bls12Fp(input.slice_to_uint(64, 96), input.slice_to_uint(96, 128))
        );
        Bls12G2 memory p = BLS12G2Affine.map_to_curve(f);
        return encode_g2(p);
    }

    function pairing(bytes memory input) public view returns (bytes memory) {
        Bls12G1 memory p = decode_g1(input.substr(0, 128));
        Bls12G2 memory q = decode_g2(input.substr(128, 256));
        Bls12G1 memory r = decode_g1(input.substr(384, 128));
        Bls12G2 memory s = decode_g2(input.substr(512, 256));
        Bls12G1[] memory a = new Bls12G1[](2);
        a[0] = p;
        a[1] = r;
        Bls12G2[] memory b = new Bls12G2[](2);
        b[0] = q;
        b[1] = s;
        return abi.encode(BLS12Pairing.pairing(a, b));
    }
}
