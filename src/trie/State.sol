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

import "../rlp/RLPDecode.sol";

/// @title State
/// @notice State specification
library State {
    using RLPDecode for RLPDecode.RLPItem;

    /// @notice EVMAccount state object
    /// @param nonce Nonce of account
    /// @param balance balance of account
    /// @param storage_root Storage root of account
    /// @param code_hash Code hash of account
    struct EVMAccount {
        uint256 nonce;
        uint256 balance;
        bytes32 storage_root;
        bytes32 code_hash;
    }

    /// @notice Convert data input to EVMAccount
    /// @param data RLP data of EVMAccount
    /// @return EVMAccount object
    function toEVMAccount(bytes memory data) internal pure returns (EVMAccount memory) {
        RLPDecode.RLPItem[] memory account = RLPDecode.readList(data);

        return EVMAccount({
            nonce: account[0].readUint256(),
            balance: account[1].readUint256(),
            storage_root: account[2].readBytes32(),
            code_hash: account[3].readBytes32()
        });
    }
}
