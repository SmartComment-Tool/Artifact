// SPDX-License-Identifier: GPL-3.0-only
pragma solidity <0.7.0 >=0.5.4 ^0.6.0 ^0.6.12;
pragma experimental ABIEncoderV2;

// ERC20.sol

/**
 * ERC20 contract interface.
 */
interface ERC20 {
    function totalSupply() external view returns (uint);
    function decimals() external view returns (uint);
    function balanceOf(address tokenOwner) external view returns (uint balance);
    function allowance(address tokenOwner, address spender) external view returns (uint remaining);
    function transfer(address to, uint tokens) external returns (bool success);
    function approve(address spender, uint tokens) external returns (bool success);
    function transferFrom(address from, address to, uint tokens) external returns (bool success);
}

// GuardianUtils.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title GuardianUtils
 * @notice Bundles guardian read logic.
 */
library GuardianUtils {

    /**
    * @notice Checks if an address is a guardian or an account authorised to sign on behalf of a smart-contract guardian
    * given a list of guardians.
    * @param _guardians the list of guardians
    * @param _guardian the address to test
    * @return true and the list of guardians minus the found guardian upon success, false and the original list of guardians if not found.
    */
    function isGuardianOrGuardianSigner(address[] memory _guardians, address _guardian) internal view returns (bool, address[] memory) {
        if (_guardians.length == 0 || _guardian == address(0)) {
            return (false, _guardians);
        }
        bool isFound = false;
        address[] memory updatedGuardians = new address[](_guardians.length - 1);
        uint256 index = 0;
        for (uint256 i = 0; i < _guardians.length; i++) {
            if (!isFound) {
                // check if _guardian is an account guardian
                if (_guardian == _guardians[i]) {
                    isFound = true;
                    continue;
                }
                // check if _guardian is the owner of a smart contract guardian
                if (isContract(_guardians[i]) && isGuardianOwner(_guardians[i], _guardian)) {
                    isFound = true;
                    continue;
                }
            }
            if (index < updatedGuardians.length) {
                updatedGuardians[index] = _guardians[i];
                index++;
            }
        }
        return isFound ? (true, updatedGuardians) : (false, _guardians);
    }

   /**
    * @notice Checks if an address is a contract.
    * @param _addr The address.
    */
    function isContract(address _addr) internal view returns (bool) {
        uint32 size;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }

    /**
    * @notice Checks if an address is the owner of a guardian contract.
    * The method does not revert if the call to the owner() method consumes more then 5000 gas.
    * @param _guardian The guardian contract
    * @param _owner The owner to verify.
    */
    function isGuardianOwner(address _guardian, address _owner) internal view returns (bool) {
        address owner = address(0);
        bytes4 sig = bytes4(keccak256("owner()"));

        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr,sig)
            let result := staticcall(5000, _guardian, ptr, 0x20, ptr, 0x20)
            if eq(result, 1) {
                owner := mload(ptr)
            }
        }
        return owner == _owner;
    }
}

// IFeature.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title IFeature
 * @notice Interface for a Feature.
 * @author Julien Niset - <julien@argent.xyz>, Olivier VDB - <olivier@argent.xyz>
 */
interface IFeature {

    enum OwnerSignature {
        Anyone,             // Anyone
        Required,           // Owner required
        Optional,           // Owner and/or guardians
        Disallowed          // guardians only
    }

    /**
    * @notice Utility method to recover any ERC20 token that was sent to the Feature by mistake.
    * @param _token The token to recover.
    */
    function recoverToken(address _token) external;

    /**
     * @notice Inits a Feature for a wallet by e.g. setting some wallet specific parameters in storage.
     * @param _wallet The wallet.
     */
    function init(address _wallet) external;

    /**
     * @notice Helper method to check if an address is an authorised feature of a target wallet.
     * @param _wallet The target wallet.
     * @param _feature The address.
     */
    function isFeatureAuthorisedInVersionManager(address _wallet, address _feature) external view returns (bool);

    /**
    * @notice Gets the number of valid signatures that must be provided to execute a
    * specific relayed transaction.
    * @param _wallet The target wallet.
    * @param _data The data of the relayed transaction.
    * @return The number of required signatures and the wallet owner signature requirement.
    */
    function getRequiredSignatures(address _wallet, bytes calldata _data) external view returns (uint256, OwnerSignature);

    /**
    * @notice Gets the list of static call signatures that this feature responds to on behalf of wallets
    */
    function getStaticCallSignatures() external view returns (bytes4[] memory);
}

// IGuardianStorage.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

interface IGuardianStorage {

    /**
     * @notice Lets an authorised module add a guardian to a wallet.
     * @param _wallet The target wallet.
     * @param _guardian The guardian to add.
     */
    function addGuardian(address _wallet, address _guardian) external;

    /**
     * @notice Lets an authorised module revoke a guardian from a wallet.
     * @param _wallet The target wallet.
     * @param _guardian The guardian to revoke.
     */
    function revokeGuardian(address _wallet, address _guardian) external;

    /**
     * @notice Checks if an account is a guardian for a wallet.
     * @param _wallet The target wallet.
     * @param _guardian The account.
     * @return true if the account is a guardian for a wallet.
     */
    function isGuardian(address _wallet, address _guardian) external view returns (bool);

    function isLocked(address _wallet) external view returns (bool);

    function getLock(address _wallet) external view returns (uint256);

    function getLocker(address _wallet) external view returns (address);

    function setLock(address _wallet, uint256 _releaseAfter) external;

    function getGuardians(address _wallet) external view returns (address[] memory);

    function guardianCount(address _wallet) external view returns (uint256);
}

// ILimitStorage.sol
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title ILimitStorage
 * @notice LimitStorage interface
 */
interface ILimitStorage {

    struct Limit {
        // the current limit
        uint128 current;
        // the pending limit if any
        uint128 pending;
        // when the pending limit becomes the current limit
        uint64 changeAfter;
    }

    struct DailySpent {
        // The amount already spent during the current period
        uint128 alreadySpent;
        // The end of the current period
        uint64 periodEnd;
    }

    function setLimit(address _wallet, Limit memory _limit) external;

    function getLimit(address _wallet) external view returns (Limit memory _limit);

    function setDailySpent(address _wallet, DailySpent memory _dailySpent) external;

    function getDailySpent(address _wallet) external view returns (DailySpent memory _dailySpent);

    function setLimitAndDailySpent(address _wallet, Limit memory _limit, DailySpent memory _dailySpent) external;

    function getLimitAndDailySpent(address _wallet) external view returns (Limit memory _limit, DailySpent memory _dailySpent);
}

// ILockStorage.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

interface ILockStorage {
    function isLocked(address _wallet) external view returns (bool);

    function getLock(address _wallet) external view returns (uint256);

    function getLocker(address _wallet) external view returns (address);

    function setLock(address _wallet, address _locker, uint256 _releaseAfter) external;
}

// IModuleRegistry.sol
// Copyright (C) 2020  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title IModuleRegistry
 * @notice Interface for the registry of authorised modules.
 */
interface IModuleRegistry {
    function registerModule(address _module, bytes32 _name) external;

    function deregisterModule(address _module) external;

    function registerUpgrader(address _upgrader, bytes32 _name) external;

    function deregisterUpgrader(address _upgrader) external;

    function recoverToken(address _token) external;

    function moduleInfo(address _module) external view returns (bytes32);

    function upgraderInfo(address _upgrader) external view returns (bytes32);

    function isRegisteredModule(address _module) external view returns (bool);

    function isRegisteredModule(address[] calldata _modules) external view returns (bool);

    function isRegisteredUpgrader(address _upgrader) external view returns (bool);
}

// IWallet.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title IWallet
 * @notice Interface for the BaseWallet
 */
interface IWallet {
    /**
     * @notice Returns the wallet owner.
     * @return The wallet owner address.
     */
    function owner() external view returns (address);

    /**
     * @notice Returns the number of authorised modules.
     * @return The number of authorised modules.
     */
    function modules() external view returns (uint);

    /**
     * @notice Sets a new owner for the wallet.
     * @param _newOwner The new owner.
     */
    function setOwner(address _newOwner) external;

    /**
     * @notice Checks if a module is authorised on the wallet.
     * @param _module The module address to check.
     * @return `true` if the module is authorised, otherwise `false`.
     */
    function authorised(address _module) external view returns (bool);

    /**
     * @notice Returns the module responsible for a static call redirection.
     * @param _sig The signature of the static call.
     * @return the module doing the redirection
     */
    function enabled(bytes4 _sig) external view returns (address);

    /**
     * @notice Enables/Disables a module.
     * @param _module The target module.
     * @param _value Set to `true` to authorise the module.
     */
    function authoriseModule(address _module, bool _value) external;

    /**
    * @notice Enables a static method by specifying the target module to which the call must be delegated.
    * @param _module The target module.
    * @param _method The static method signature.
    */
    function enableStaticCall(address _module, bytes4 _method) external;
}

// SafeMath.sol

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

// Utils.sol
// Copyright (C) 2020  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title Utils
 * @notice Common utility methods used by modules.
 */
library Utils {

    /**
    * @notice Helper method to recover the signer at a given position from a list of concatenated signatures.
    * @param _signedHash The signed hash
    * @param _signatures The concatenated signatures.
    * @param _index The index of the signature to recover.
    */
    function recoverSigner(bytes32 _signedHash, bytes memory _signatures, uint _index) internal pure returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        // we jump 32 (0x20) as the first slot of bytes contains the length
        // we jump 65 (0x41) per signature
        // for v we load 32 bytes ending with v (the first 31 come from s) then apply a mask
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(_signatures, add(0x20,mul(0x41,_index))))
            s := mload(add(_signatures, add(0x40,mul(0x41,_index))))
            v := and(mload(add(_signatures, add(0x41,mul(0x41,_index)))), 0xff)
        }
        require(v == 27 || v == 28);

        address recoveredAddress = ecrecover(_signedHash, v, r, s);
        require(recoveredAddress != address(0), "Utils: ecrecover returned 0");
        return recoveredAddress;
    }

    /**
    * @notice Helper method to parse data and extract the method signature.
    */
    function functionPrefix(bytes memory _data) internal pure returns (bytes4 prefix) {
        require(_data.length >= 4, "RM: Invalid functionPrefix");
        // solhint-disable-next-line no-inline-assembly
        assembly {
            prefix := mload(add(_data, 0x20))
        }
    }

    /**
    * @notice Returns ceil(a / b).
    */
    function ceil(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a / b;
        if (a % b == 0) {
            return c;
        } else {
            return c + 1;
        }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a < b) {
            return a;
        }
        return b;
    }
}

// IVersionManager.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title IVersionManager
 * @notice Interface for the VersionManager module.
 * @author Olivier VDB - <olivier@argent.xyz>
 */
interface IVersionManager {
    /**
     * @notice Returns true if the feature is authorised for the wallet
     * @param _wallet The target wallet.
     * @param _feature The feature.
     */
    function isFeatureAuthorised(address _wallet, address _feature) external view returns (bool);

    /**
     * @notice Lets a feature (caller) invoke a wallet.
     * @param _wallet The target wallet.
     * @param _to The target address for the transaction.
     * @param _value The value of the transaction.
     * @param _data The data of the transaction.
     */
    function checkAuthorisedFeatureAndInvokeWallet(
        address _wallet,
        address _to,
        uint256 _value,
        bytes calldata _data
    ) external returns (bytes memory _res);

    /* ******* Backward Compatibility with old Storages and BaseWallet *************** */

    /**
     * @notice Sets a new owner for the wallet.
     * @param _newOwner The new owner.
     */
    function setOwner(address _wallet, address _newOwner) external;

    /**
     * @notice Lets a feature write data to a storage contract.
     * @param _wallet The target wallet.
     * @param _storage The storage contract.
     * @param _data The data of the call
     */
    function invokeStorage(address _wallet, address _storage, bytes calldata _data) external;

    /**
     * @notice Upgrade a wallet to a new version.
     * @param _wallet the wallet to upgrade
     * @param _toVersion the new version
     */
    function upgradeWallet(address _wallet, uint256 _toVersion) external;
 
}

// BaseFeature.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.s

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title BaseFeature
 * @notice Base Feature contract that contains methods common to all Feature contracts.
 * @author Julien Niset - <julien@argent.xyz>, Olivier VDB - <olivier@argent.xyz>
 */
contract BaseFeature is IFeature {

    // Empty calldata
    bytes constant internal EMPTY_BYTES = "";
    // Mock token address for ETH
    address constant internal ETH_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    // The address of the Lock storage
    ILockStorage internal lockStorage;
    // The address of the Version Manager
    IVersionManager internal versionManager;

    event FeatureCreated(bytes32 name);

    /**
     * @notice Throws if the wallet is locked.
     */
    modifier onlyWhenUnlocked(address _wallet) {
        require(!lockStorage.isLocked(_wallet), "BF: wallet locked");
        _;
    }

    /**
     * @notice Throws if the sender is not the VersionManager.
     */
    modifier onlyVersionManager() {
        require(msg.sender == address(versionManager), "BF: caller must be VersionManager");
        _;
    }

    /**
     * @notice Throws if the sender is not the owner of the target wallet.
     */
    modifier onlyWalletOwner(address _wallet) {
        require(isOwner(_wallet, msg.sender), "BF: must be wallet owner");
        _;
    }

    /**
     * @notice Throws if the sender is not an authorised feature of the target wallet.
     */
    modifier onlyWalletFeature(address _wallet) {
        require(versionManager.isFeatureAuthorised(_wallet, msg.sender), "BF: must be a wallet feature");
        _;
    }

    /**
     * @notice Throws if the sender is not the owner of the target wallet or the feature itself.
     */
    modifier onlyWalletOwnerOrFeature(address _wallet) {
        // Wrapping in an internal method reduces deployment cost by avoiding duplication of inlined code
        verifyOwnerOrAuthorisedFeature(_wallet, msg.sender);
        _;
    }

    constructor(
        ILockStorage _lockStorage,
        IVersionManager _versionManager,
        bytes32 _name
    ) public {
        lockStorage = _lockStorage;
        versionManager = _versionManager;
        emit FeatureCreated(_name);
    }

    /**
    * 
    */
    function recoverToken(address _token) external virtual override {
        uint total = ERC20(_token).balanceOf(address(this));
        _token.call(abi.encodeWithSelector(ERC20(_token).transfer.selector, address(versionManager), total));
    }

    /**
     * @notice Inits the feature for a wallet by doing nothing.
     * @dev !! Overriding methods need make sure `init()` can only be called by the VersionManager !!
     * @param _wallet The wallet.
     */
    function init(address _wallet) external virtual override  {}

    /**
     * 
     */
    function getRequiredSignatures(address, bytes calldata) external virtual view override returns (uint256, OwnerSignature) {
        revert("BF: disabled method");
    }

    /**
     * 
     */
    function getStaticCallSignatures() external virtual override view returns (bytes4[] memory _sigs) {}

    /**
     * 
     */
    function isFeatureAuthorisedInVersionManager(address _wallet, address _feature) public override view returns (bool) {
        return versionManager.isFeatureAuthorised(_wallet, _feature);
    }

    /**
    * @notice Checks that the wallet address provided as the first parameter of _data matches _wallet
    * @return false if the addresses are different.
    */
    function verifyData(address _wallet, bytes calldata _data) internal pure returns (bool) {
        require(_data.length >= 36, "RM: Invalid dataWallet");
        address dataWallet = abi.decode(_data[4:], (address));
        return dataWallet == _wallet;
    }
    
     /**
     * @notice Helper method to check if an address is the owner of a target wallet.
     * @param _wallet The target wallet.
     * @param _addr The address.
     */
    function isOwner(address _wallet, address _addr) internal view returns (bool) {
        return IWallet(_wallet).owner() == _addr;
    }

    /**
     * @notice Verify that the caller is an authorised feature or the wallet owner.
     * @param _wallet The target wallet.
     * @param _sender The caller.
     */
    function verifyOwnerOrAuthorisedFeature(address _wallet, address _sender) internal view {
        require(isFeatureAuthorisedInVersionManager(_wallet, _sender) || isOwner(_wallet, _sender), "BF: must be owner or feature");
    }

    /**
     * @notice Helper method to invoke a wallet.
     * @param _wallet The target wallet.
     * @param _to The target address for the transaction.
     * @param _value The value of the transaction.
     * @param _data The data of the transaction.
     */
    function invokeWallet(address _wallet, address _to, uint256 _value, bytes memory _data)
        internal
        returns (bytes memory _res) 
    {
        _res = versionManager.checkAuthorisedFeatureAndInvokeWallet(_wallet, _to, _value, _data);
    }

}

// GuardianManager.sol
// Copyright (C) 2018  Argent Labs Ltd. <https://argent.xyz>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

/**
 * @title GuardianManager
 * @notice Module to manage the guardians of wallets.
 * Guardians are accounts (EOA or contracts) that are authorized to perform specific security operations on wallet
 * such as toggle a safety lock, start a recovery procedure, or confirm transactions.
 * Addition or revokation of guardians is initiated by the owner of a wallet and must be confirmed after a security period (e.g. 24 hours).
 * The list of guardians for a wallet is stored on a separate contract to facilitate its use by other modules.
 * @author Julien Niset - <julien@argent.xyz>
 * @author Olivier Van Den Biggelaar - <olivier@argent.xyz>
 */
contract GuardianManager is BaseFeature {

    bytes32 constant NAME = "GuardianManager";

    bytes4 constant internal CONFIRM_ADDITION_PREFIX = bytes4(keccak256("confirmGuardianAddition(address,address)"));
    bytes4 constant internal CONFIRM_REVOKATION_PREFIX = bytes4(keccak256("confirmGuardianRevokation(address,address)"));

    struct GuardianManagerConfig {
        // The time at which a guardian addition or revokation will be confirmable by the owner
        mapping (bytes32 => uint256) pending;
    }

    // The wallet specific storage
    mapping (address => GuardianManagerConfig) internal configs;
    // The security period
    uint256 public securityPeriod;
    // The security window
    uint256 public securityWindow;
    // The guardian storage
    IGuardianStorage public guardianStorage;

    // *************** Events *************************** //

    event GuardianAdditionRequested(address indexed wallet, address indexed guardian, uint256 executeAfter);
    event GuardianRevokationRequested(address indexed wallet, address indexed guardian, uint256 executeAfter);
    event GuardianAdditionCancelled(address indexed wallet, address indexed guardian);
    event GuardianRevokationCancelled(address indexed wallet, address indexed guardian);
    event GuardianAdded(address indexed wallet, address indexed guardian);
    event GuardianRevoked(address indexed wallet, address indexed guardian);

    // *************** Constructor ********************** //

    constructor(
        ILockStorage _lockStorage,
        IGuardianStorage _guardianStorage,
        IVersionManager _versionManager,
        uint256 _securityPeriod,
        uint256 _securityWindow
    )
        BaseFeature(_lockStorage, _versionManager, NAME)
        public
    {
        guardianStorage = _guardianStorage;
        securityPeriod = _securityPeriod;
        securityWindow = _securityWindow;
    }

    // *************** External Functions ********************* //

    /**
     * @notice Lets the owner add a guardian to its wallet.
     * The first guardian is added immediately. All following additions must be confirmed
     * by calling the confirmGuardianAddition() method.
     * @param _wallet The target wallet.
     * @param _guardian The guardian to add.
     */
    function addGuardian(address _wallet, address _guardian) external onlyWalletOwnerOrFeature(_wallet) onlyWhenUnlocked(_wallet) {
        require(!isOwner(_wallet, _guardian), "GM: target guardian cannot be owner");
        require(!isGuardian(_wallet, _guardian), "GM: target is already a guardian");
        // Guardians must either be an EOA or a contract with an owner()
        // method that returns an address with a 5000 gas stipend.
        // Note that this test is not meant to be strict and can be bypassed by custom malicious contracts.
        (bool success,) = _guardian.call{gas: 5000}(abi.encodeWithSignature("owner()"));
        require(success, "GM: guardian must be EOA or implement owner()");
        if (guardianStorage.guardianCount(_wallet) == 0) {
            doAddGuardian(_wallet, _guardian);
            emit GuardianAdded(_wallet, _guardian);
        } else {
            bytes32 id = keccak256(abi.encodePacked(_wallet, _guardian, "addition"));
            GuardianManagerConfig storage config = configs[_wallet];
            require(
                config.pending[id] == 0 || block.timestamp > config.pending[id] + securityWindow,
                "GM: addition of target as guardian is already pending");
            config.pending[id] = block.timestamp + securityPeriod;
            emit GuardianAdditionRequested(_wallet, _guardian, block.timestamp + securityPeriod);
        }
    }

    /**
     * @notice Confirms the pending addition of a guardian to a wallet.
     * The method must be called during the confirmation window and can be called by anyone to enable orchestration.
     * @param _wallet The target wallet.
     * @param _guardian The guardian.
     */
    function confirmGuardianAddition(address _wallet, address _guardian) external onlyWhenUnlocked(_wallet) {
        bytes32 id = keccak256(abi.encodePacked(_wallet, _guardian, "addition"));
        GuardianManagerConfig storage config = configs[_wallet];
        require(config.pending[id] > 0, "GM: no pending addition as guardian for target");
        require(config.pending[id] < block.timestamp, "GM: Too early to confirm guardian addition");
        require(block.timestamp < config.pending[id] + securityWindow, "GM: Too late to confirm guardian addition");
        doAddGuardian(_wallet, _guardian);
        emit GuardianAdded(_wallet, _guardian);
        delete config.pending[id];
    }

    /**
     * @notice Lets the owner cancel a pending guardian addition.
     * @param _wallet The target wallet.
     * @param _guardian The guardian.
     */
    function cancelGuardianAddition(address _wallet, address _guardian) external onlyWalletOwnerOrFeature(_wallet) onlyWhenUnlocked(_wallet) {
        bytes32 id = keccak256(abi.encodePacked(_wallet, _guardian, "addition"));
        GuardianManagerConfig storage config = configs[_wallet];
        require(config.pending[id] > 0, "GM: no pending addition as guardian for target");
        delete config.pending[id];
        emit GuardianAdditionCancelled(_wallet, _guardian);
    }

    /**
     * @notice Lets the owner revoke a guardian from its wallet.
     * @dev Revokation must be confirmed by calling the confirmGuardianRevokation() method.
     * @param _wallet The target wallet.
     * @param _guardian The guardian to revoke.
     */
    function revokeGuardian(address _wallet, address _guardian) external onlyWalletOwnerOrFeature(_wallet) {
        require(isGuardian(_wallet, _guardian), "GM: must be an existing guardian");
        bytes32 id = keccak256(abi.encodePacked(_wallet, _guardian, "revokation"));
        GuardianManagerConfig storage config = configs[_wallet];
        require(
            config.pending[id] == 0 || block.timestamp > config.pending[id] + securityWindow,
            "GM: revokation of target as guardian is already pending"); // TODO need to allow if confirmation window passed
        config.pending[id] = block.timestamp + securityPeriod;
        emit GuardianRevokationRequested(_wallet, _guardian, block.timestamp + securityPeriod);
    }

    /**
     * @notice Confirms the pending revokation of a guardian to a wallet.
     * The method must be called during the confirmation window and can be called by anyone to enable orchestration.
     * @param _wallet The target wallet.
     * @param _guardian The guardian.
     */
    function confirmGuardianRevokation(address _wallet, address _guardian) external {
        bytes32 id = keccak256(abi.encodePacked(_wallet, _guardian, "revokation"));
        GuardianManagerConfig storage config = configs[_wallet];
        require(config.pending[id] > 0, "GM: no pending guardian revokation for target");
        require(config.pending[id] < block.timestamp, "GM: Too early to confirm guardian revokation");
        require(block.timestamp < config.pending[id] + securityWindow, "GM: Too late to confirm guardian revokation");
        doRevokeGuardian(_wallet, _guardian);
        emit GuardianRevoked(_wallet, _guardian);
        delete config.pending[id];
    }

    /**
     * @notice Lets the owner cancel a pending guardian revokation.
     * @param _wallet The target wallet.
     * @param _guardian The guardian.
     */
    function cancelGuardianRevokation(address _wallet, address _guardian) external onlyWalletOwnerOrFeature(_wallet) onlyWhenUnlocked(_wallet) {
        bytes32 id = keccak256(abi.encodePacked(_wallet, _guardian, "revokation"));
        GuardianManagerConfig storage config = configs[_wallet];
        require(config.pending[id] > 0, "GM: no pending guardian revokation for target");
        delete config.pending[id];
        emit GuardianRevokationCancelled(_wallet, _guardian);
    }

    /**
     * @notice Checks if an address is a guardian for a wallet.
     * @param _wallet The target wallet.
     * @param _guardian The address to check.
     * @return _isGuardian `true` if the address is a guardian for the wallet otherwise `false`.
     */
    function isGuardian(address _wallet, address _guardian) public view returns (bool _isGuardian) {
        _isGuardian = guardianStorage.isGuardian(_wallet, _guardian);
    }

    /**
    * @notice Checks if an address is a guardian or an account authorised to sign on behalf of a smart-contract guardian.
    * @param _wallet The target wallet.
    * @param _guardian the address to test
    * @return _isGuardian `true` if the address is a guardian for the wallet otherwise `false`.
    */
    function isGuardianOrGuardianSigner(address _wallet, address _guardian) external view returns (bool _isGuardian) {
        (_isGuardian, ) = GuardianUtils.isGuardianOrGuardianSigner(guardianStorage.getGuardians(_wallet), _guardian);
    }

    /**
     * @notice Counts the number of active guardians for a wallet.
     * @param _wallet The target wallet.
     * @return _count The number of active guardians for a wallet.
     */
    function guardianCount(address _wallet) external view returns (uint256 _count) {
        return guardianStorage.guardianCount(_wallet);
    }

    /**
     * @notice Get the active guardians for a wallet.
     * @param _wallet The target wallet.
     * @return _guardians the active guardians for a wallet.
     */
    function getGuardians(address _wallet) external view returns (address[] memory _guardians) {
        return guardianStorage.getGuardians(_wallet);
    }

    /**
     * 
     */
    function getRequiredSignatures(address _wallet, bytes calldata _data) external view override returns (uint256, OwnerSignature) {
        bytes4 methodId = Utils.functionPrefix(_data);
        if (methodId == CONFIRM_ADDITION_PREFIX || methodId == CONFIRM_REVOKATION_PREFIX) {
            return (0, OwnerSignature.Anyone);
        } else {
            return (1, OwnerSignature.Required);
        }
    }

    // *************** Internal Functions ********************* //

    function doAddGuardian(address _wallet, address _guardian) internal {
        versionManager.invokeStorage(
            _wallet,
            address(guardianStorage), 
            abi.encodeWithSelector(guardianStorage.addGuardian.selector, _wallet, _guardian)
        );
    }
    
    function doRevokeGuardian(address _wallet, address _guardian) internal {
        versionManager.invokeStorage(
            _wallet,
            address(guardianStorage), 
            abi.encodeWithSelector(guardianStorage.revokeGuardian.selector, _wallet, _guardian)
        );
    }
}
