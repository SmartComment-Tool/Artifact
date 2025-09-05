// SPDX-License-Identifier: MIT
pragma solidity =0.8.18 ^0.8.0 ^0.8.11;

// @openzeppelin/contracts/interfaces/IERC1271.sol

/**
 * @dev Interface of the ERC1271 standard signature validation method for
 * contracts as defined in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].
 *
 * _Available since v4.1._
 */
interface IERC1271 {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param hash      Hash of the data to be signed
     * @param signature Signature byte array associated with _data
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}

// @openzeppelin/contracts/security/ReentrancyGuard.sol

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}

// @openzeppelin/contracts/token/ERC20/IERC20.sol

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// @openzeppelin/contracts/token/ERC721/IERC721Receiver.sol

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

// @openzeppelin/contracts/utils/Address.sol

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

// @openzeppelin/contracts/utils/Context.sol

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}

// @openzeppelin/contracts/utils/cryptography/ECDSA.sol

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        } else if (error == RecoverError.InvalidSignatureV) {
            revert("ECDSA: invalid signature 'v' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            return tryRecover(hash, r, vs);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address, RecoverError) {
        bytes32 s;
        uint8 v;
        assembly {
            s := and(vs, 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
            v := add(shr(255, vs), 27)
        }
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        if (v != 27 && v != 28) {
            return (address(0), RecoverError.InvalidSignatureV);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

// @openzeppelin/contracts/utils/introspection/IERC165.sol

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// contracts/errors/MigrationErrors.sol

/**
 * @title MigrationErrors
 * @author Non-Fungible Technologies, Inc.
 *
 * This file contains all custom errors for v3 migration contracts from competitor lending protocol #1.
 * All errors are prefixed by "MR_" for MigrationRollover. Errors are located in one place to make it
 * possible to holistically look at all migratin over failure cases.
 */

// ================================== LP1 To V3 Migration ====================================

/**
 * @notice The flash loan callback caller is not recognized. The caller must be the flash
 *         loan provider.
 *
 * @param caller                  The address of the caller.
 * @param lendingPool             Expected address of the flash loan provider.
 */
error MR_UnknownCaller(address caller, address lendingPool);

/**
 * @notice The balance of the borrower is insufficient to repay the difference between
 *         the loan and the V3 loan principal minus fees.
 *
 * @param borrower                The address of the borrower.
 * @param amount                  The difference amount.
 * @param balance                 Current balance of the borrower.
 */
error MR_InsufficientFunds(address borrower, uint256 amount, uint256 balance);

/**
 * @notice The allowance of the borrower to the V3 migration contract is insufficient
 *          to repay the difference between the LP1 loan and the V3 loan principal minus fees.
 *
 * @param borrower                The address of the borrower.
 * @param amount                  The difference amount.
 * @param allowance               Current allowance of the borrower.
 */
error MR_InsufficientAllowance(address borrower, uint256 amount, uint256 allowance);

/**
 * @notice An accounting check to verify that either the leftover V3 loan principal is
 *         zero or the amount needed from the borrower to cover any difference is zero.
 *         Either there is leftover principal that needs to be sent to the borrower, or
 *         the borrower needs to send funds to cover the difference between the LP1 repayment
 *         amount and the new V3 loan principal minus any fees.
 *
 * @param leftoverPrincipal       The leftover principal from the V3 loan.
 * @param needFromBorrower        The amount needed from the borrower to cover the difference.
 */
error MR_FundsConflict(uint256 leftoverPrincipal, uint256 needFromBorrower);

/**
 * @notice After repaying the LP1 loan, the LP1 -> V3 migration contract must be the owner of
 *         the collateral token.
 *
 * @param owner                   The owner of the collateral token.
 */
error MR_NotCollateralOwner(address owner);

/**
 * @notice Only the holder of the obligationReceiptToken can migrate their loan.
 *
 * @param caller                  The address of the caller.
 * @param borrower                Holder of the obligationReceiptToken address
 */
error MR_CallerNotBorrower(address caller, address borrower);

/**
 * @notice The LP1 and V3 payable currency tokens must be the same so that the flash loan can
 *         be repaid.
 *
 * @param oldCurrency               The payable currency address for the old loan.
 * @param v3Currency                The V3 payable currency address.
 */
error MR_CurrencyMismatch(address oldCurrency, address v3Currency);

/**
 * @notice The LP1 and V3 collateral tokens must be the same.
 *
 * @param oldCollateral             The collateral token address for the old loan.
 * @param v3Collateral              The V3 collateral token address.
 */
error MR_CollateralMismatch(address oldCollateral, address v3Collateral);

/**
 * @notice The LP1 and V3 collateral token IDs must be the same.
 *
 * @param oldCollateralId           The old collateral token ID for the old loan.
 * @param v3CollateralId            The V3 collateral token ID.
 */
error MR_CollateralIdMismatch(uint256 oldCollateralId, uint256 v3CollateralId);

/**
 * @notice Contract is paused, migration operations are blocked.
 */
error MR_Paused();

// contracts/errors/RolloverErrors.sol

/**
 * @title RolloverErrors
 * @author Non-Fungible Technologies, Inc.
 *
 * This file contains all custom errors for V2 -> V3 rollover contracts. All errors are
 * prefixed by "R_" for Rollover. Errors are located in one place to make it possible to
 * holistically look at all V2 -> V3 rollover failure cases.
 */

// ================================== V2 To V3 Rollover ====================================

/**
 * @notice The flash loan callback caller is not recognized. The caller must be the flash
 *         loan provider.
 *
 * @param caller                  The address of the caller.
 * @param lendingPool             Expected address of the flash loan provider.
 */
error R_UnknownCaller(address caller, address lendingPool);

/**
 * @notice The balance of the borrower is insufficient to repay the difference between
 *         the V2 loan and the V3 loan principal minus fees.
 *
 * @param borrower                The address of the borrower.
 * @param amount                  The difference amount.
 * @param balance                 Current balance of the borrower.
 */
error R_InsufficientFunds(address borrower, uint256 amount, uint256 balance);

/**
 * @notice The allowance of the borrower to the V2 -> V3 rollover contract is insufficient
 *          to repay the difference between the V2 loan and the V3 loan principal minus fees.
 *
 * @param borrower                The address of the borrower.
 * @param amount                  The difference amount.
 * @param allowance               Current allowance of the borrower.
 */
error R_InsufficientAllowance(address borrower, uint256 amount, uint256 allowance);

/**
 * @notice An accounting check to verify that either the leftover V3 loan principal is
 *         zero or the amount needed from the borrower to cover any difference is zero.
 *         Either there is leftover principal that needs to be sent to the borrower, or
 *         the borrower needs to send funds to cover the difference between the V2 repayment
 *         amount and the new V3 loan principal minus any fees.
 *
 * @param leftoverPrincipal       The leftover principal from the V3 loan.
 * @param needFromBorrower        The amount needed from the borrower to cover the difference.
 */
error R_FundsConflict(uint256 leftoverPrincipal, uint256 needFromBorrower);

/**
 * @notice After repaying the V2 loan, the V2 -> V3 rollover contract must be the owner of
 *         the collateral token.
 *
 * @param owner                   The owner of the collateral token.
 */
error R_NotCollateralOwner(address owner);

/**
 * @notice Only the holder of the borrowerNote can rollover their loan.
 *
 * @param caller                  The address of the caller.
 * @param borrower                Holder of the borrower notes address
 */
error R_CallerNotBorrower(address caller, address borrower);

/**
 * @notice The V2 and V3 payable currency tokens must be the same so that the flash loan can
 *         be repaid.
 *
 * @param v2Currency              The V2 payable currency address.
 * @param v3Currency              The V3 payable currency address.
 */
error R_CurrencyMismatch(address v2Currency, address v3Currency);

/**
 * @notice The V2 and V3 collateral tokens must be the same.
 *
 * @param v2Collateral            The V2 collateral token address.
 * @param v3Collateral            The V3 collateral token address.
 */
error R_CollateralMismatch(address v2Collateral, address v3Collateral);

/**
 * @notice The V2 and V3 collateral token IDs must be the same.
 *
 * @param v2CollateralId          The V2 collateral token ID.
 * @param v3CollateralId          The V3 collateral token ID.
 */
error R_CollateralIdMismatch(uint256 v2CollateralId, uint256 v3CollateralId);

/**
 * @notice The rollover contract does not hold a balance for the token specified to flush.
 */
error R_NoTokenBalance();

/**
 * @notice Contract is paused, rollover operations are blocked.
 */
error R_Paused();

/**
 * @notice The rollover contract is already in the specified pause state.
 */
error R_StateAlreadySet();

/**
 * @notice Cannot pass the zero address as an argument.
 *
 * @param name                    The name of the contract.
 */
error R_ZeroAddress(string name);

/**
 * @notice The borrower address saved in the rollover contract is not the same as the
 *         borrower address provided in the flash loan operation data. The initiator of
 *         the flash loan must be the rollover contract.
 *
 * @param providedBorrower        Borrower address passed in the flash loan operation data.
 * @param cachedBorrower          Borrower address saved in the rollover contract.
 */
error R_UnknownBorrower(address providedBorrower, address cachedBorrower);

/**
 * @notice The borrower state must be address(0) to initiate a rollover sequence.
 *
 * @param borrower                The borrower address.
 */
error R_BorrowerNotReset(address borrower);

// contracts/external/lp-1/airdrop/IAirdropReceiverFactory.sol

/**
 * @title IAirdropReceiver
 * @author NFTfi
 * @dev
 */
interface IAirdropReceiverFactory {
    function createAirdropReceiver(address _to) external returns (address, uint256);
}

// contracts/external/lp-1/interfaces/IAirdropFlashLoan.sol

interface IAirdropFlashLoan {
    function pullAirdrop(
        address _nftCollateralContract,
        uint256 _nftCollateralId,
        address _nftWrapper,
        address _target,
        bytes calldata _data,
        address _nftAirdrop,
        uint256 _nftAirdropId,
        bool _is1155,
        uint256 _nftAirdropAmount,
        address _beneficiary
    ) external;
}

// contracts/external/lp-1/interfaces/IBundleBuilder.sol

interface IBundleBuilder {
    /**
     * @notice data of a erc721 bundle element
     *
     * @param tokenContract - address of the token contract
     * @param id - id of the token
     * @param safeTransferable - wether the implementing token contract has a safeTransfer function or not
     */
    struct BundleElementERC721 {
        address tokenContract;
        uint256 id;
        bool safeTransferable;
    }

    /**
     * @notice data of a erc20 bundle element
     *
     * @param tokenContract - address of the token contract
     * @param amount - amount of the token
     */
    struct BundleElementERC20 {
        address tokenContract;
        uint256 amount;
    }

    /**
     * @notice data of a erc20 bundle element
     *
     * @param tokenContract - address of the token contract
     * @param ids - list of ids of the tokens
     * @param amounts - list amounts of the tokens
     */
    struct BundleElementERC1155 {
        address tokenContract;
        uint256[] ids;
        uint256[] amounts;
    }

    /**
     * @notice the lists of erc721-20-1155 tokens that are to be bundled
     *
     * @param erc721s list of erc721 tokens
     * @param erc20s list of erc20 tokens
     * @param erc1155s list of erc1155 tokens
     */
    struct BundleElements {
        BundleElementERC721[] erc721s;
        BundleElementERC20[] erc20s;
        BundleElementERC1155[] erc1155s;
    }

    /**
     * @notice used by the loan contract to build a bundle from the BundleElements struct at the beginning of a loan,
     * returns the id of the created bundle
     *
     * @param _bundleElements - the lists of erc721-20-1155 tokens that are to be bundled
     * @param _sender sender of the tokens in the bundle - the borrower
     * @param _receiver receiver of the created bundle, normally the loan contract
     */
    function buildBundle(
        BundleElements memory _bundleElements,
        address _sender,
        address _receiver
    ) external returns (uint256);

    /**
     * @notice Remove all the children from the bundle
     * @dev This method may run out of gas if the list of children is too big. In that case, children can be removed
     *      individually.
     * @param _tokenId the id of the bundle
     * @param _receiver address of the receiver of the children
     */
    function decomposeBundle(uint256 _tokenId, address _receiver) external;
}

// contracts/external/lp-1/interfaces/IDirectLoanCoordinator.sol

/**
 * @title IDirectLoanCoordinator
 * @author NFTfi
 * @dev DirectLoanCoordinator interface.
 */
interface IDirectLoanCoordinator {
    enum StatusType {
        NOT_EXISTS,
        NEW,
        RESOLVED
    }

    /**
     * @notice This struct contains data related to a loan
     *
     * @param smartNftId - The id of both the promissory note and obligation receipt.
     * @param status - The status in which the loan currently is.
     * @param loanContract - Address of the LoanType contract that created the loan.
     */
    struct Loan {
        address loanContract;
        uint64 smartNftId;
        StatusType status;
    }

    function registerLoan(address _lender, bytes32 _loanType) external returns (uint32);

    function mintObligationReceipt(uint32 _loanId, address _borrower) external;

    function resolveLoan(uint32 _loanId) external;

    function promissoryNoteToken() external view returns (address);

    function obligationReceiptToken() external view returns (address);

    function getLoanData(uint32 _loanId) external view returns (Loan memory);

    function isValidLoanId(uint32 _loanId, address _loanContract) external view returns (bool);
}

// contracts/external/lp-1/interfaces/INftWrapper.sol

/**
 * @title INftTypeRegistry
 * @author NFTfi
 * @dev Interface for NFT Wrappers.
 */
interface INftWrapper {
    function transferNFT(
        address from,
        address to,
        address nftContract,
        uint256 tokenId
    ) external returns (bool);

    function isOwner(
        address owner,
        address nftContract,
        uint256 tokenId
    ) external view returns (bool);

    function wrapAirdropReceiver(
        address _recipient,
        address _nftContract,
        uint256 _nftId,
        address _beneficiary
    ) external returns (bool);
}

// contracts/external/lp-1/interfaces/INftfiHub.sol

/**
 * @title INftfiHub
 * @author NFTfi
 * @dev NftfiHub interface
 */
interface INftfiHub {
    function setContract(string calldata _contractKey, address _contractAddress) external;

    function getContract(bytes32 _contractKey) external view returns (address);
}

// contracts/external/lp-1/interfaces/IPermittedERC20s.sol

interface IPermittedERC20s {
    function getERC20Permit(address _erc20) external view returns (bool);
}

// contracts/external/lp-1/interfaces/IPermittedNFTs.sol

interface IPermittedNFTs {
    function setNFTPermit(address _nftContract, string memory _nftType) external;

    function getNFTPermit(address _nftContract) external view returns (bytes32);

    function getNFTWrapper(address _nftContract) external view returns (address);
}

// contracts/external/lp-1/interfaces/IPermittedPartners.sol

interface IPermittedPartners {
    function getPartnerPermit(address _partner) external view returns (uint16);
}

// contracts/external/lp-1/loans/direct/loanTypes/LoanData.sol

/**
 * @title  LoanData
 * @author NFTfi
 * @notice An interface containg the main Loan struct shared by Direct Loans types.
 */
interface LoanData {
    /* ********** */
    /* DATA TYPES */
    /* ********** */

    /**
     * @notice The main Loan Terms struct. This data is saved upon loan creation.
     *
     * @param loanERC20Denomination - The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * @param loanPrincipalAmount - The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param maximumRepaymentAmount - The maximum amount of money that the borrower would be required to retrieve their
     * collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always have
     * to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * @param nftCollateralContract - The address of the the NFT collateral contract.
     * @param nftCollateralWrapper - The NFTfi wrapper of the NFT collateral contract.
     * @param nftCollateralId - The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * @param loanStartTime - The block.timestamp when the loan first began (measured in seconds).
     * @param loanDuration - The amount of time (measured in seconds) that can elapse before the lender can liquidate
     * the loan and seize the underlying collateral NFT.
     * @param loanInterestRateForDurationInBasisPoints - This is the interest rate (measured in basis points, e.g.
     * hundreths of a percent) for the loan, that must be repaid pro-rata by the borrower at the conclusion of the loan
     * or risk seizure of their nft collateral. Note if the type of the loan is fixed then this value  is not used and
     * is irrelevant so it should be set to 0.
     * @param loanAdminFeeInBasisPoints - The percent (measured in basis points) of the interest earned that will be
     * taken as a fee by the contract admins when the loan is repaid. The fee is stored in the loan struct to prevent an
     * attack where the contract admins could adjust the fee right before a loan is repaid, and take all of the interest
     * earned.
     * @param borrower
     */
    struct LoanTerms {
        uint256 loanPrincipalAmount;
        uint256 maximumRepaymentAmount;
        uint256 nftCollateralId;
        address loanERC20Denomination;
        uint32 loanDuration;
        uint16 loanInterestRateForDurationInBasisPoints;
        uint16 loanAdminFeeInBasisPoints;
        address nftCollateralWrapper;
        uint64 loanStartTime;
        address nftCollateralContract;
        address borrower;
    }

    /**
     * @notice Some extra Loan's settings struct. This data is saved upon loan creation.
     * We need this to avoid stack too deep errors.
     *
     * @param revenueSharePartner - The address of the partner that will receive the revenue share.
     * @param revenueShareInBasisPoints - The percent (measured in basis points) of the admin fee amount that will be
     * taken as a revenue share for a t
     * @param referralFeeInBasisPoints - The percent (measured in basis points) of the loan principal amount that will
     * be taken as a fee to pay to the referrer, 0 if the lender is not paying referral fee.he partner, at the moment
     * the loan is begun.
     */
    struct LoanExtras {
        address revenueSharePartner;
        uint16 revenueShareInBasisPoints;
        uint16 referralFeeInBasisPoints;
    }

    /**
     * @notice The offer made by the lender. Used as parameter on both acceptOffer (initiated by the borrower) and
     * acceptListing (initiated by the lender).
     *
     * @param loanERC20Denomination - The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * @param loanPrincipalAmount - The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param maximumRepaymentAmount - The maximum amount of money that the borrower would be required to retrieve their
     *  collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always
     * have to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * @param nftCollateralContract - The address of the ERC721 contract of the NFT collateral.
     * @param nftCollateralId - The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * @param referrer - The address of the referrer who found the lender matching the listing, Zero address to signal
     * this there is no referrer.
     * @param loanDuration - The amount of time (measured in seconds) that can elapse before the lender can liquidate
     * the loan and seize the underlying collateral NFT.
     * @param loanAdminFeeInBasisPoints - The percent (measured in basis points) of the interest earned that will be
     * taken as a fee by the contract admins when the loan is repaid. The fee is stored in the loan struct to prevent an
     * attack where the contract admins could adjust the fee right before a loan is repaid, and take all of the interest
     * earned.
     */
    struct Offer {
        uint256 loanPrincipalAmount;
        uint256 maximumRepaymentAmount;
        uint256 nftCollateralId;
        address nftCollateralContract;
        uint32 loanDuration;
        uint16 loanAdminFeeInBasisPoints;
        address loanERC20Denomination;
        address referrer;
    }

    /**
     * @notice Signature related params. Used as parameter on both acceptOffer (containing borrower signature) and
     * acceptListing (containing lender signature).
     *
     * @param signer - The address of the signer. The borrower for `acceptOffer` the lender for `acceptListing`.
     * @param nonce - The nonce referred here is not the same as an Ethereum account's nonce.
     * We are referring instead to a nonce that is used by the lender or the borrower when they are first signing
     * off-chain NFTfi orders. These nonce can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     * - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     * - Second, it allows a user to cancel an off-chain order by calling NFTfi.cancelLoanCommitmentBeforeLoanHasBegun()
     * , which marks the nonce as used and prevents any future loan from using the user's off-chain order that contains
     * that nonce.
     * @param expiry - Date when the signature expires
     * @param signature - The ECDSA signature of the borrower or the lender, obtained off-chain ahead of time, signing
     * the following combination of parameters:
     * - Borrower
     *   - ListingTerms.loanERC20Denomination,
     *   - ListingTerms.minLoanPrincipalAmount,
     *   - ListingTerms.maxLoanPrincipalAmount,
     *   - ListingTerms.nftCollateralContract,
     *   - ListingTerms.nftCollateralId,
     *   - ListingTerms.revenueSharePartner,
     *   - ListingTerms.minLoanDuration,
     *   - ListingTerms.maxLoanDuration,
     *   - ListingTerms.maxInterestRateForDurationInBasisPoints,
     *   - ListingTerms.referralFeeInBasisPoints,
     *   - Signature.signer,
     *   - Signature.nonce,
     *   - Signature.expiry,
     *   - address of the loan type contract
     *   - chainId
     * - Lender:
     *   - Offer.loanERC20Denomination
     *   - Offer.loanPrincipalAmount
     *   - Offer.maximumRepaymentAmount
     *   - Offer.nftCollateralContract
     *   - Offer.nftCollateralId
     *   - Offer.referrer
     *   - Offer.loanDuration
     *   - Offer.loanAdminFeeInBasisPoints
     *   - Signature.signer,
     *   - Signature.nonce,
     *   - Signature.expiry,
     *   - address of the loan type contract
     *   - chainId
     */
    struct Signature {
        uint256 nonce;
        uint256 expiry;
        address signer;
        bytes signature;
    }

    /**
     * @notice Some extra parameters that the borrower needs to set when accepting an offer.
     *
     * @param revenueSharePartner - The address of the partner that will receive the revenue share.
     * @param referralFeeInBasisPoints - The percent (measured in basis points) of the loan principal amount that will
     * be taken as a fee to pay to the referrer, 0 if the lender is not paying referral fee.
     */
    struct BorrowerSettings {
        address revenueSharePartner;
        uint16 referralFeeInBasisPoints;
    }

    /**
     * @notice Terms the borrower set off-chain and is willing to accept automatically when fulfiled by a lender's
     * offer.
     *
     * @param loanERC20Denomination - The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * @param minLoanPrincipalAmount - The minumum sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param maxLoanPrincipalAmount - The  sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param maximumRepaymentAmount - The maximum amount of money that the borrower would be required to retrieve their
     * collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always have
     * to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * @param nftCollateralContract - The address of the ERC721 contract of the NFT collateral.
     * @param nftCollateralId - The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * @param revenueSharePartner - The address of the partner that will receive the revenue share.
     * @param minLoanDuration - The minumum amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param maxLoanDuration - The maximum amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param maxInterestRateForDurationInBasisPoints - This is maximum the interest rate (measured in basis points,
     * e.g. hundreths of a percent) for the loan.
     * @param referralFeeInBasisPoints - The percent (measured in basis points) of the loan principal amount that will
     * be taken as a fee to pay to the referrer, 0 if the lender is not paying referral fee.
     */
    struct ListingTerms {
        uint256 minLoanPrincipalAmount;
        uint256 maxLoanPrincipalAmount;
        uint256 nftCollateralId;
        address nftCollateralContract;
        uint32 minLoanDuration;
        uint32 maxLoanDuration;
        uint16 maxInterestRateForDurationInBasisPoints;
        uint16 referralFeeInBasisPoints;
        address revenueSharePartner;
        address loanERC20Denomination;
    }
}

// contracts/external/lp-1/utils/ContractKeys.sol

/**
 * @title ContractKeys
 * @author NFTfi
 * @dev Common library for contract keys
 */
library ContractKeys {
    bytes32 public constant PERMITTED_ERC20S = bytes32("PERMITTED_ERC20S");
    bytes32 public constant PERMITTED_NFTS = bytes32("PERMITTED_NFTS");
    bytes32 public constant PERMITTED_PARTNERS = bytes32("PERMITTED_PARTNERS");
    bytes32 public constant NFT_TYPE_REGISTRY = bytes32("NFT_TYPE_REGISTRY");
    bytes32 public constant LOAN_REGISTRY = bytes32("LOAN_REGISTRY");
    bytes32 public constant PERMITTED_SNFT_RECEIVER = bytes32("PERMITTED_SNFT_RECEIVER");
    bytes32 public constant PERMITTED_BUNDLE_ERC20S = bytes32("PERMITTED_BUNDLE_ERC20S");
    bytes32 public constant PERMITTED_AIRDROPS = bytes32("PERMITTED_AIRDROPS");
    bytes32 public constant AIRDROP_RECEIVER = bytes32("AIRDROP_RECEIVER");
    bytes32 public constant AIRDROP_FACTORY = bytes32("AIRDROP_FACTORY");
    bytes32 public constant AIRDROP_FLASH_LOAN = bytes32("AIRDROP_FLASH_LOAN");
    bytes32 public constant NFTFI_BUNDLER = bytes32("NFTFI_BUNDLER");

    string public constant AIRDROP_WRAPPER_STRING = "AirdropWrapper";

    /**
     * @notice Returns the bytes32 representation of a string
     * @param _key the string key
     * @return id bytes32 representation
     */
    function getIdFromStringKey(string memory _key) external pure returns (bytes32 id) {
        require(bytes(_key).length <= 32, "invalid key");

        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := mload(add(_key, 32))
        }
    }
}

// contracts/interfaces/IFeeController.sol

interface IFeeController {
    // ================ Structs ================

    struct FeesOrigination {
        uint16 borrowerOriginationFee;
        uint16 lenderOriginationFee;
        uint16 lenderDefaultFee;
        uint16 lenderInterestFee;
        uint16 lenderPrincipalFee;
    }

    struct FeesRollover {
        uint16 borrowerRolloverFee;
        uint16 lenderRolloverFee;
    }

    // ================ Events =================

    event SetLendingFee(bytes32 indexed id, uint16 fee);

    event SetVaultMintFee(uint64 fee);

    // ================ Getter/Setter =================

    function setLendingFee(bytes32 id, uint16 fee) external;

    function setVaultMintFee(uint64 fee) external;

    function getLendingFee(bytes32 id) external view returns (uint16);

    function getVaultMintFee() external view returns (uint64);

    function getFeesOrigination() external view returns (FeesOrigination memory);

    function getFeesRollover() external view returns (FeesRollover memory);

    function getMaxLendingFee(bytes32 id) external view returns (uint16);

    function getMaxVaultMintFee() external view returns (uint64);
}

// contracts/interfaces/INFTWithDescriptor.sol

interface INFTWithDescriptor {
    // ============= Events ==============

    event SetDescriptor(address indexed caller, address indexed descriptor);

    // ================ Resource Metadata ================

    function tokenURI(uint256 tokenId) external view returns (string memory);

    function setDescriptor(address descriptor) external;
}

// contracts/libraries/LoanLibrary.sol

/**
 * @title LoanLibrary
 * @author Non-Fungible Technologies, Inc.
 *
 * Contains all data types used across Arcade lending contracts.
 */
library LoanLibrary {
    /**
     * @dev Enum describing the current state of a loan.
     * State change flow:
     * Created -> Active -> Repaid
     *                   -> Defaulted
     */
    enum LoanState {
        // We need a default that is not 'Created' - this is the zero value
        DUMMY_DO_NOT_USE,
        // The loan has been initialized, funds have been delivered to the borrower and the collateral is held.
        Active,
        // The loan has been repaid, and the collateral has been returned to the borrower. This is a terminal state.
        Repaid,
        // The loan was delinquent and collateral claimed by the lender. This is a terminal state.
        Defaulted
    }

    /**
     * @dev The raw terms of a loan.
     */
    struct LoanTerms {
        // Interest expressed as a rate, unlike V1 gross value.
        // Input conversion: 0.01% = (1 * 10**18) ,  10.00% = (1000 * 10**18)
        // This represents the rate over the lifetime of the loan, not APR.
        // 0.01% is the minimum interest rate allowed by the protocol.
        uint256 proratedInterestRate;
        /// @dev Full-slot variables
        // The amount of principal in terms of the payableCurrency.
        uint256 principal;
        // The token ID of the address holding the collateral.
        /// @dev Can be an AssetVault, or the NFT contract for unbundled collateral
        address collateralAddress;
        /// @dev Packed variables
        // The number of seconds representing relative due date of the loan.
        /// @dev Max is 94,608,000, fits in 96 bits
        uint96 durationSecs;
        // The token ID of the collateral.
        uint256 collateralId;
        // The payable currency for the loan principal and interest.
        address payableCurrency;
        // Timestamp for when signature for terms expires
        uint96 deadline;
        // Affiliate code used to start the loan.
        bytes32 affiliateCode;
    }

    /**
     * @dev Modification of loan terms, used for signing only.
     *      Instead of a collateralId, a list of predicates
     *      is defined by 'bytes' in items.
     */
    struct LoanTermsWithItems {
        // Interest expressed as a rate, unlike V1 gross value.
        // Input conversion: 0.01% = (1 * 10**18) ,  10.00% = (1000 * 10**18)
        // This represents the rate over the lifetime of the loan, not APR.
        // 0.01% is the minimum interest rate allowed by the protocol.
        uint256 proratedInterestRate;
        /// @dev Full-slot variables
        // The amount of principal in terms of the payableCurrency.
        uint256 principal;
        // The tokenID of the address holding the collateral
        address collateralAddress;
        /// @dev Packed variables
        // The number of seconds representing relative due date of the loan.
        /// @dev Max is 94,608,000, fits in 96 bits
        uint96 durationSecs;
        // An encoded list of predicates, along with their verifiers.
        bytes items;
        // The payable currency for the loan principal and interest.
        address payableCurrency;
        // Timestamp for when signature for terms expires
        uint96 deadline;
        // Affiliate code used to start the loan.
        bytes32 affiliateCode;
    }

    /**
     * @dev Predicate for item-based verifications
     */
    struct Predicate {
        // The encoded predicate, to decoded and parsed by the verifier contract.
        bytes data;
        // The verifier contract.
        address verifier;
    }

    /**
     * @dev Snapshot of lending fees at the time of loan creation.
     */
    struct FeeSnapshot {
        // The fee taken when lender claims defaulted collateral.
        uint16 lenderDefaultFee;
        // The fee taken from the borrower's interest repayment.
        uint16 lenderInterestFee;
        // The fee taken from the borrower's principal repayment.
        uint16 lenderPrincipalFee;
    }

    /**
     * @dev The data of a loan. This is stored once the loan is Active
     */
    struct LoanData {
        /// @dev Packed variables
        // The current state of the loan.
        LoanState state;
        // Start date of the loan, using block.timestamp.
        uint160 startDate;
        /// @dev Full-slot variables
        // The raw terms of the loan.
        LoanTerms terms;
        // Record of lending fees at the time of loan creation.
        FeeSnapshot feeSnapshot;
    }
}

// contracts/v2-migration/v2-contracts/LoanLibraryV2.sol

/**
 * @title LoanLibrary
 * @author Non-Fungible Technologies, Inc.
 *
 * Contains all data types used across Arcade lending contracts.
 */
library LoanLibraryV2 {
    /**
     * @dev Enum describing the current state of a loan.
     * State change flow:
     * Created -> Active -> Repaid
     *                   -> Defaulted
     */
    enum LoanState {
        // We need a default that is not 'Created' - this is the zero value
        DUMMY_DO_NOT_USE,
        // The loan has been initialized, funds have been delivered to the borrower and the collateral is held.
        Active,
        // The loan has been repaid, and the collateral has been returned to the borrower. This is a terminal state.
        Repaid,
        // The loan was delinquent and collateral claimed by the lender. This is a terminal state.
        Defaulted
    }

    /**
     * @dev The raw terms of a loan.
     */
    struct LoanTerms {
        /// @dev Packed variables
        // The number of seconds representing relative due date of the loan.
        /// @dev Max is 94,608,000, fits in 32 bits
        uint32 durationSecs;
        // Timestamp for when signature for terms expires
        uint32 deadline;
        // Total number of installment periods within the loan duration.
        /// @dev Max is 1,000,000, fits in 24 bits
        uint24 numInstallments;
        // Interest expressed as a rate, unlike V1 gross value.
        // Input conversion: 0.01% = (1 * 10**18) ,  10.00% = (1000 * 10**18)
        // This represents the rate over the lifetime of the loan, not APR.
        // 0.01% is the minimum interest rate allowed by the protocol.
        /// @dev Max is 10,000%, fits in 160 bits
        uint160 interestRate;
        /// @dev Full-slot variables
        // The amount of principal in terms of the payableCurrency.
        uint256 principal;
        // The token ID of the address holding the collateral.
        /// @dev Can be an AssetVault, or the NFT contract for unbundled collateral
        address collateralAddress;
        // The token ID of the collateral.
        uint256 collateralId;
        // The payable currency for the loan principal and interest.
        address payableCurrency;
    }

    /**
     * @dev Modification of loan terms, used for signing only.
     *      Instead of a collateralId, a list of predicates
     *      is defined by 'bytes' in items.
     */
    struct LoanTermsWithItems {
        /// @dev Packed variables
        // The number of seconds representing relative due date of the loan.
        /// @dev Max is 94,608,000, fits in 32 bits
        uint32 durationSecs;
        // Timestamp for when signature for terms expires
        uint32 deadline;
        // Total number of installment periods within the loan duration.
        /// @dev Max is 1,000,000, fits in 24 bits
        uint24 numInstallments;
        // Interest expressed as a rate, unlike V1 gross value.
        // Input conversion: 0.01% = (1 * 10**18) ,  10.00% = (1000 * 10**18)
        // This represents the rate over the lifetime of the loan, not APR.
        // 0.01% is the minimum interest rate allowed by the protocol.
        /// @dev Max is 10,000%, fits in 160 bits
        uint160 interestRate;
        /// @dev Full-slot variables
        uint256 principal;
        // The tokenID of the address holding the collateral
        /// @dev Must be an AssetVault for LoanTermsWithItems
        address collateralAddress;
        // An encoded list of predicates
        bytes items;
        // The payable currency for the loan principal and interest
        address payableCurrency;
    }

    /**
     * @dev Predicate for item-based verifications
     */
    struct Predicate {
        // The encoded predicate, to decoded and parsed by the verifier contract
        bytes data;
        // The verifier contract
        address verifier;
    }

    /**
     * @dev The data of a loan. This is stored once the loan is Active
     */
    struct LoanData {
        /// @dev Packed variables
        // The current state of the loan
        LoanState state;
        // Number of installment payments made on the loan
        uint24 numInstallmentsPaid;
        // installment loan specific
        // Start date of the loan, using block.timestamp - for determining installment period
        uint160 startDate;
        /// @dev Full-slot variables
        // The raw terms of the loan
        LoanTerms terms;
        // Remaining balance of the loan. Starts as equal to principal. Can reduce based on
        // payments made, can increased based on compounded interest from missed payments and late fees
        uint256 balance;
        // Amount paid in total by the borrower
        uint256 balancePaid;
        // Total amount of late fees accrued
        uint256 lateFeesAccrued;
    }
}

// contracts/v2-migration/v2-contracts/v2-interfaces/IFeeControllerV2.sol

interface IFeeControllerV2 {
    // ================ Events =================

    event UpdateOriginationFee(uint256 _newFee);
    event UpdateRolloverFee(uint256 _newFee);
    event UpdateCollateralSaleFee(uint256 _newFee);
    event UpdatePayLaterFee(uint256 _newFee);

    // ================ Fee Setters =================

    function setOriginationFee(uint256 _originationFee) external;

    function setRolloverFee(uint256 _rolloverFee) external;

    function setCollateralSaleFee(uint256 _collateralSaleFee) external;

    function setPayLaterFee(uint256 _payLaterFee) external;

    // ================ Fee Getters =================

    function getOriginationFee() external view returns (uint256);

    function getRolloverFee() external view returns (uint256);

    function getCollateralSaleFee() external view returns (uint256);

    function getPayLaterFee() external view returns (uint256);
}

// contracts/v2-migration/v2-contracts/v2-interfaces/IRepaymentControllerV2.sol

interface IRepaymentControllerV2 {
    // ============== Lifeycle Operations ==============

    function repay(uint256 loanId) external;

    function claim(uint256 loanId) external;

    function repayPartMinimum(uint256 loanId) external;

    function repayPart(uint256 loanId, uint256 amount) external;

    function closeLoan(uint256 loanId) external;

    // ============== View Functions ==============

    function getInstallmentMinPayment(uint256 loanId)
        external
        view
        returns (
            uint256,
            uint256,
            uint256
        );

    function amountToCloseLoan(uint256 loanId) external returns (uint256, uint256);

    function getFullInterestAmount(uint256 principal, uint256 interestRate) external pure returns (uint256);
}

// @openzeppelin/contracts/access/Ownable.sol

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _setOwner(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _setOwner(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _setOwner(newOwner);
    }

    function _setOwner(address newOwner) private {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// @openzeppelin/contracts/security/Pausable.sol

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract Pausable is Context {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    constructor() {
        _paused = false;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        require(paused(), "Pausable: not paused");
        _;
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}

// @openzeppelin/contracts/token/ERC1155/IERC1155.sol

/**
 * @dev Required interface of an ERC1155 compliant contract, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1155[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155 is IERC165 {
    /**
     * @dev Emitted when `value` tokens of token type `id` are transferred from `from` to `to` by `operator`.
     */
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    /**
     * @dev Equivalent to multiple {TransferSingle} events, where `operator`, `from` and `to` are the same for all
     * transfers.
     */
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );

    /**
     * @dev Emitted when `account` grants or revokes permission to `operator` to transfer their tokens, according to
     * `approved`.
     */
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    /**
     * @dev Emitted when the URI for token type `id` changes to `value`, if it is a non-programmatic URI.
     *
     * If an {URI} event was emitted for `id`, the standard
     * https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[guarantees] that `value` will equal the value
     * returned by {IERC1155MetadataURI-uri}.
     */
    event URI(string value, uint256 indexed id);

    /**
     * @dev Returns the amount of tokens of token type `id` owned by `account`.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory);

    /**
     * @dev Grants or revokes permission to `operator` to transfer the caller's tokens, according to `approved`,
     *
     * Emits an {ApprovalForAll} event.
     *
     * Requirements:
     *
     * - `operator` cannot be the caller.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns true if `operator` is approved to transfer ``account``'s tokens.
     *
     * See {setApprovalForAll}.
     */
    function isApprovedForAll(address account, address operator) external view returns (bool);

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If the caller is not `from`, it must be have been approved to spend ``from``'s tokens via {setApprovalForAll}.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}

// @openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol

/**
 * @dev _Available since v3.1._
 */
interface IERC1155Receiver is IERC165 {
    /**
        @dev Handles the receipt of a single ERC1155 token type. This function is
        called at the end of a `safeTransferFrom` after the balance has been updated.
        To accept the transfer, this must return
        `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
        (i.e. 0xf23a6e61, or its own function selector).
        @param operator The address which initiated the transfer (i.e. msg.sender)
        @param from The address which previously owned the token
        @param id The ID of the token being transferred
        @param value The amount of tokens being transferred
        @param data Additional data with no specified format
        @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed
    */
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);

    /**
        @dev Handles the receipt of a multiple ERC1155 token types. This function
        is called at the end of a `safeBatchTransferFrom` after the balances have
        been updated. To accept the transfer(s), this must return
        `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
        (i.e. 0xbc197c81, or its own function selector).
        @param operator The address which initiated the batch transfer (i.e. msg.sender)
        @param from The address which previously owned the token
        @param ids An array containing ids of each token being transferred (order and length must match values array)
        @param values An array containing amounts of each token being transferred (order and length must match ids array)
        @param data Additional data with no specified format
        @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if transfer is allowed
    */
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

// @openzeppelin/contracts/token/ERC721/IERC721.sol

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 tokenId
    ) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external;
}

// @openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol

/**
 * @dev Implementation of the {IERC721Receiver} interface.
 *
 * Accepts all token transfers.
 * Make sure the contract is able to use its token with {IERC721-safeTransferFrom}, {IERC721-approve} or {IERC721-setApprovalForAll}.
 */
contract ERC721Holder is IERC721Receiver {
    /**
     * @dev See {IERC721Receiver-onERC721Received}.
     *
     * Always returns `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

// contracts/external/interfaces/IFlashLoanRecipient.sol

interface IFlashLoanRecipient {
    /**
     * @dev When `flashLoan` is called on the Vault, it invokes the `receiveFlashLoan` hook on the recipient.
     *
     * At the time of the call, the Vault will have transferred `amounts` for `tokens` to the recipient. Before this
     * call returns, the recipient must have transferred `amounts` plus `feeAmounts` for each token back to the
     * Vault, or else the entire flash loan will revert.
     *
     * `userData` is the same value passed in the `IVault.flashLoan` call.
     */
    function receiveFlashLoan(
        IERC20[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory userData
    ) external;
}

interface IVault {
    /**
     * @dev copied from @balancer-labs/v2-vault/contracts/interfaces/IVault.sol,
     *      which uses an incompatible compiler version. Only necessary selectors
     *      (flashLoan) included.
     */
    function flashLoan(
        IFlashLoanRecipient recipient,
        IERC20[] memory tokens,
        uint256[] memory amounts,
        bytes memory userData
    ) external;
}

// contracts/external/lp-1/loans/direct/loanTypes/IDirectLoanBase.sol

interface IDirectLoanBase {
    function maximumLoanDuration() external view returns (uint256);

    function adminFeeInBasisPoints() external view returns (uint16);

    // solhint-disable-next-line func-name-mixedcase
    function LOAN_COORDINATOR() external view returns (bytes32);

    function loanIdToLoan(uint32)
        external
        view
        returns (
            uint256,
            uint256,
            uint256,
            address,
            uint32,
            uint16,
            uint16,
            address,
            uint64,
            address,
            address
        );

    function loanRepaidOrLiquidated(uint32) external view returns (bool);

    function getWhetherNonceHasBeenUsedForUser(address _user, uint256 _nonce) external view returns (bool);
}

// contracts/interfaces/IOriginationController.sol

interface IOriginationController {
    // ================ Data Types =============

    struct Currency {
        bool isAllowed;
        uint256 minPrincipal;
    }

    enum Side {
        BORROW,
        LEND
    }

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes extraData;
    }

    struct RolloverAmounts {
        uint256 needFromBorrower;
        uint256 leftoverPrincipal;
        uint256 amountFromLender;
        uint256 amountToOldLender;
        uint256 amountToLender;
        uint256 amountToBorrower;
    }

    // ================ Events =================

    event Approval(address indexed owner, address indexed signer, bool isApproved);
    event SetAllowedVerifier(address indexed verifier, bool isAllowed);
    event SetAllowedCurrency(address indexed currency, bool isAllowed, uint256 minPrincipal);
    event SetAllowedCollateral(address indexed collateral, bool isAllowed);

    // ============== Origination Operations ==============

    function initializeLoan(
        LoanLibrary.LoanTerms calldata loanTerms,
        address borrower,
        address lender,
        Signature calldata sig,
        uint160 nonce
    ) external returns (uint256 loanId);

    function initializeLoanWithItems(
        LoanLibrary.LoanTerms calldata loanTerms,
        address borrower,
        address lender,
        Signature calldata sig,
        uint160 nonce,
        LoanLibrary.Predicate[] calldata itemPredicates
    ) external returns (uint256 loanId);

    function initializeLoanWithCollateralPermit(
        LoanLibrary.LoanTerms calldata loanTerms,
        address borrower,
        address lender,
        Signature calldata sig,
        uint160 nonce,
        Signature calldata collateralSig,
        uint256 permitDeadline
    ) external returns (uint256 loanId);

    function initializeLoanWithCollateralPermitAndItems(
        LoanLibrary.LoanTerms calldata loanTerms,
        address borrower,
        address lender,
        Signature calldata sig,
        uint160 nonce,
        Signature calldata collateralSig,
        uint256 permitDeadline,
        LoanLibrary.Predicate[] calldata itemPredicates
    ) external returns (uint256 loanId);

    function rolloverLoan(
        uint256 oldLoanId,
        LoanLibrary.LoanTerms calldata loanTerms,
        address lender,
        Signature calldata sig,
        uint160 nonce
    ) external returns (uint256 newLoanId);

    function rolloverLoanWithItems(
        uint256 oldLoanId,
        LoanLibrary.LoanTerms calldata loanTerms,
        address lender,
        Signature calldata sig,
        uint160 nonce,
        LoanLibrary.Predicate[] calldata itemPredicates
    ) external returns (uint256 newLoanId);

    // ================ Permission Management =================

    function approve(address signer, bool approved) external;

    function isApproved(address owner, address signer) external returns (bool);

    function isSelfOrApproved(address target, address signer) external returns (bool);

    function isApprovedForContract(
        address target,
        Signature calldata sig,
        bytes32 sighash
    ) external returns (bool);

    // ============== Signature Verification ==============

    function recoverTokenSignature(
        LoanLibrary.LoanTerms calldata loanTerms,
        Signature calldata sig,
        uint160 nonce,
        Side side
    ) external view returns (bytes32 sighash, address signer);

    function recoverItemsSignature(
        LoanLibrary.LoanTerms calldata loanTerms,
        Signature calldata sig,
        uint160 nonce,
        Side side,
        bytes32 itemsHash
    ) external view returns (bytes32 sighash, address signer);

    // ============== Admin Operations ==============

    function setAllowedPayableCurrencies(address[] memory _tokenAddress, Currency[] calldata currencyData) external;

    function setAllowedCollateralAddresses(address[] memory _tokenAddress, bool[] calldata isAllowed) external;

    function setAllowedVerifiers(address[] calldata verifiers, bool[] calldata isAllowed) external;

    function isAllowedCurrency(address token) external view returns (bool);

    function isAllowedCollateral(address token) external view returns (bool);

    function isAllowedVerifier(address verifier) external view returns (bool);
}

// @openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol

/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    function safeTransfer(
        IERC20 token,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(
        IERC20 token,
        address from,
        address to,
        uint256 value
    ) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) {
            // Return data is optional
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// @openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol

/**
 * @title ERC-721 Non-Fungible Token Standard, optional enumeration extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Enumerable is IERC721 {
    /**
     * @dev Returns the total amount of tokens stored by the contract.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns a token ID owned by `owner` at a given `index` of its token list.
     * Use along with {balanceOf} to enumerate all of ``owner``'s tokens.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);

    /**
     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.
     * Use along with {totalSupply} to enumerate all tokens.
     */
    function tokenByIndex(uint256 index) external view returns (uint256);
}

// @openzeppelin/contracts/utils/cryptography/SignatureChecker.sol

/**
 * @dev Signature verification helper: Provide a single mechanism to verify both private-key (EOA) ECDSA signature and
 * ERC1271 contract sigantures. Using this instead of ECDSA.recover in your contract will make them compatible with
 * smart contract wallets such as Argent and Gnosis.
 *
 * Note: unlike ECDSA signatures, contract signature's are revocable, and the outcome of this function can thus change
 * through time. It could return true at block N and false at block N+1 (or the opposite).
 *
 * _Available since v4.1._
 */
library SignatureChecker {
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
        if (error == ECDSA.RecoverError.NoError && recovered == signer) {
            return true;
        }

        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature)
        );
        return (success && result.length == 32 && abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
    }
}

// contracts/v2-migration/v2-contracts/v2-interfaces/IPromissoryNoteV2.sol

interface IPromissoryNoteV2 is IERC721Enumerable {
    // ============== Token Operations ==============

    function mint(address to, uint256 loanId) external returns (uint256);

    function burn(uint256 tokenId) external;

    function setPaused(bool paused) external;

    // ============== Initializer ==============

    function initialize(address loanCore) external;
}

// contracts/external/lp-1/loans/BaseLoan.sol

/**
 * @title  BaseLoan
 * @author NFTfi
 * @dev Implements base functionalities common to all Loan types.
 * Mostly related to governance and security.
 */
abstract contract BaseLoan is Ownable, Pausable, ReentrancyGuard {
    /* *********** */
    /* CONSTRUCTOR */
    /* *********** */

    /**
     * @notice Sets the admin of the contract.
     *
     * @param _admin - Initial admin of this contract.
     */
    constructor(address _admin) {
        // solhint-disable-previous-line no-empty-blocks
    }

    /* ********* */
    /* FUNCTIONS */
    /* ********* */

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - Only the owner can call this method.
     * - The contract must not be paused.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - Only the owner can call this method.
     * - The contract must be paused.
     */
    function unpause() external onlyOwner {
        _unpause();
    }
}

// contracts/external/lp-1/utils/NftReceiver.sol

/**
 * @title NftReceiver
 * @author NFTfi
 * @dev Base contract with capabilities for receiving ERC1155 and ERC721 tokens
 */
abstract contract NftReceiver is IERC1155Receiver, ERC721Holder {
    /**
     *  @dev Handles the receipt of a single ERC1155 token type. This function is called at the end of a
     * `safeTransferFrom` after the balance has been updated.
     * @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if allowed
     */
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external virtual override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    /**
     *  @dev Handles the receipt of a multiple ERC1155 token types. This function is called at the end of a
     * `safeBatchTransferFrom` after the balances have been updated.
     *  @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if allowed
     */
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    ) external virtual override returns (bytes4) {
        revert("ERC1155 batch not supported");
    }

    /**
     * @dev Checks whether this contract implements the interface defined by `interfaceId`.
     * @param _interfaceId Id of the interface
     * @return true if this contract implements the interface
     */
    function supportsInterface(bytes4 _interfaceId) public view virtual override returns (bool) {
        return
            _interfaceId == type(IERC1155Receiver).interfaceId ||
            _interfaceId == type(IERC721Receiver).interfaceId ||
            _interfaceId == type(IERC165).interfaceId;
    }
}

// contracts/interfaces/IPromissoryNote.sol

interface IPromissoryNote is INFTWithDescriptor, IERC721Enumerable {
    // ============== Token Operations ==============

    function mint(address to, uint256 loanId) external returns (uint256);

    function burn(uint256 tokenId) external;

    // ============== Initializer ==============

    function initialize(address loanCore) external;
}

// contracts/external/lp-1/utils/NFTfiSigningUtils.sol

/**
 * @title  NFTfiSigningUtils
 * @author NFTfi
 * @notice Helper contract for NFTfi. This contract manages verifying signatures from off-chain NFTfi orders.
 * Based on the version of this same contract used on NFTfi V1
 */
library NFTfiSigningUtils {
    /* ********* */
    /* FUNCTIONS */
    /* ********* */

    /**
     * @dev This function gets the current chain ID.
     */
    function getChainID() public view returns (uint256) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * @notice This function is when the lender accepts a borrower's binding listing terms, to validate the lender's
     * signature that the borrower provided off-chain to verify that it did indeed made such listing.
     *
     * @param _listingTerms - The listing terms struct containing:
     * - loanERC20Denomination: The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * - minLoanPrincipalAmount: The minumum sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * - maxLoanPrincipalAmount: The  sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * - maximumRepaymentAmount: The maximum amount of money that the borrower would be required to retrieve their
     * collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always have
     * to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * - nftCollateralContract: The address of the ERC721 contract of the NFT collateral.
     * - nftCollateralId: The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * - revenueSharePartner: The address of the partner that will receive the revenue share.
     * - minLoanDuration: The minumum amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * - maxLoanDuration: The maximum amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * - maxInterestRateForDurationInBasisPoints: This is maximum the interest rate (measured in basis points, e.g.
     * hundreths of a percent) for the loan, that must be repaid pro-rata by the borrower at the conclusion of the loan
     * or risk seizure of their nft collateral. Note if the type of the loan is fixed then this value  is not used and
     * is irrelevant so it should be set to 0.
     * - referralFeeInBasisPoints: The percent (measured in basis points) of the loan principal amount that will be
     * taken as a fee to pay to the referrer, 0 if the lender is not paying referral fee.
     * @param _signature - The offer struct containing:
     * - signer: The address of the signer. The borrower for `acceptOffer` the lender for `acceptListing`.
     * - nonce: The nonce referred here is not the same as an Ethereum account's nonce.
     * We are referring instead to a nonce that is used by the lender or the borrower when they are first signing
     * off-chain NFTfi orders. These nonce can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     *   - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     *   - Second, it allows a user to cancel an off-chain order by calling
     * NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the nonce as used and prevents any future loan from
     * using the user's off-chain order that contains that nonce.
     * - expiry: Date when the signature expires
     * - signature: The ECDSA signature of the borrower, obtained off-chain ahead of time, signing the following
     * combination of parameters:
     *   - listingTerms.loanERC20Denomination,
     *   - listingTerms.minLoanPrincipalAmount,
     *   - listingTerms.maxLoanPrincipalAmount,
     *   - listingTerms.nftCollateralContract,
     *   - listingTerms.nftCollateralId,
     *   - listingTerms.revenueSharePartner,
     *   - listingTerms.minLoanDuration,
     *   - listingTerms.maxLoanDuration,
     *   - listingTerms.maxInterestRateForDurationInBasisPoints,
     *   - listingTerms.referralFeeInBasisPoints,
     *   - signature.signer,
     *   - signature.nonce,
     *   - signature.expiry,
     *   - address of this contract
     *   - chainId
     */
    function isValidBorrowerSignature(LoanData.ListingTerms memory _listingTerms, LoanData.Signature memory _signature)
        external
        view
        returns (bool)
    {
        return isValidBorrowerSignature(_listingTerms, _signature, address(this));
    }

    /**
     * @dev This function overload the previous function to allow the caller to specify the address of the contract
     *
     */
    function isValidBorrowerSignature(
        LoanData.ListingTerms memory _listingTerms,
        LoanData.Signature memory _signature,
        address _loanContract
    ) public view returns (bool) {
        require(block.timestamp <= _signature.expiry, "Borrower Signature has expired");
        require(_loanContract != address(0), "Loan is zero address");
        if (_signature.signer == address(0)) {
            return false;
        } else {
            bytes32 message = keccak256(
                abi.encodePacked(
                    getEncodedListing(_listingTerms),
                    getEncodedSignature(_signature),
                    _loanContract,
                    getChainID()
                )
            );

            return
                SignatureChecker.isValidSignatureNow(
                    _signature.signer,
                    ECDSA.toEthSignedMessageHash(message),
                    _signature.signature
                );
        }
    }

    /**
     * @notice This function is when the lender accepts a borrower's binding listing terms, to validate the lender's
     * signature that the borrower provided off-chain to verify that it did indeed made such listing.
     *
     * @param _listingTerms - The listing terms struct containing:
     * - loanERC20Denomination: The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * - minLoanPrincipalAmount: The minumum sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * - maxLoanPrincipalAmount: The  sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * - maximumRepaymentAmount: The maximum amount of money that the borrower would be required to retrieve their
     * collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always have
     * to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * - nftCollateralContract: The address of the ERC721 contract of the NFT collateral.
     * - nftCollateralId: The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * - revenueSharePartner: The address of the partner that will receive the revenue share.
     * - minLoanDuration: The minumum amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * - maxLoanDuration: The maximum amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * - maxInterestRateForDurationInBasisPoints: This is maximum the interest rate (measured in basis points, e.g.
     * hundreths of a percent) for the loan, that must be repaid pro-rata by the borrower at the conclusion of the loan
     * or risk seizure of their nft collateral. Note if the type of the loan is fixed then this value  is not used and
     * is irrelevant so it should be set to 0.
     * - referralFeeInBasisPoints: The percent (measured in basis points) of the loan principal amount that will be
     * taken as a fee to pay to the referrer, 0 if the lender is not paying referral fee.
     * @param _bundleElements - the lists of erc721-20-1155 tokens that are to be bundled
     * @param _signature - The offer struct containing:
     * - signer: The address of the signer. The borrower for `acceptOffer` the lender for `acceptListing`.
     * - nonce: The nonce referred here is not the same as an Ethereum account's nonce.
     * We are referring instead to a nonce that is used by the lender or the borrower when they are first signing
     * off-chain NFTfi orders. These nonce can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     *   - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     *   - Second, it allows a user to cancel an off-chain order by calling
     * NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the nonce as used and prevents any future loan from
     * using the user's off-chain order that contains that nonce.
     * - expiry: Date when the signature expires
     * - signature: The ECDSA signature of the borrower, obtained off-chain ahead of time, signing the following
     * combination of parameters:
     *   - listingTerms.loanERC20Denomination,
     *   - listingTerms.minLoanPrincipalAmount,
     *   - listingTerms.maxLoanPrincipalAmount,
     *   - listingTerms.nftCollateralContract,
     *   - listingTerms.nftCollateralId,
     *   - listingTerms.revenueSharePartner,
     *   - listingTerms.minLoanDuration,
     *   - listingTerms.maxLoanDuration,
     *   - listingTerms.maxInterestRateForDurationInBasisPoints,
     *   - listingTerms.referralFeeInBasisPoints,
     *   - bundleElements
     *   - signature.signer,
     *   - signature.nonce,
     *   - signature.expiry,
     *   - address of this contract
     *   - chainId
     */
    function isValidBorrowerSignatureBundle(
        LoanData.ListingTerms memory _listingTerms,
        IBundleBuilder.BundleElements memory _bundleElements,
        LoanData.Signature memory _signature
    ) external view returns (bool) {
        return isValidBorrowerSignatureBundle(_listingTerms, _bundleElements, _signature, address(this));
    }

    /**
     * @dev This function overload the previous function to allow the caller to specify the address of the contract
     *
     */
    function isValidBorrowerSignatureBundle(
        LoanData.ListingTerms memory _listingTerms,
        IBundleBuilder.BundleElements memory _bundleElements,
        LoanData.Signature memory _signature,
        address _loanContract
    ) public view returns (bool) {
        require(block.timestamp <= _signature.expiry, "Borrower Signature has expired");
        require(_loanContract != address(0), "Loan is zero address");
        if (_signature.signer == address(0)) {
            return false;
        } else {
            bytes32 message = keccak256(
                abi.encodePacked(
                    getEncodedListing(_listingTerms),
                    abi.encode(_bundleElements),
                    getEncodedSignature(_signature),
                    _loanContract,
                    getChainID()
                )
            );

            return
                SignatureChecker.isValidSignatureNow(
                    _signature.signer,
                    ECDSA.toEthSignedMessageHash(message),
                    _signature.signature
                );
        }
    }

    /**
     * @notice This function is when the borrower accepts a lender's offer, to validate the lender's signature that the
     * lender provided off-chain to verify that it did indeed made such offer.
     *
     * @param _offer - The offer struct containing:
     * - loanERC20Denomination: The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * - loanPrincipalAmount: The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * - maximumRepaymentAmount: The maximum amount of money that the borrower would be required to retrieve their
     * collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always have
     * to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * - nftCollateralContract: The address of the ERC721 contract of the NFT collateral.
     * - nftCollateralId: The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * - referrer: The address of the referrer who found the lender matching the listing, Zero address to signal
     * this there is no referrer.
     * - loanDuration: The amount of time (measured in seconds) that can elapse before the lender can liquidate the
     * loan and seize the underlying collateral NFT.
     * - loanInterestRateForDurationInBasisPoints: This is the interest rate (measured in basis points, e.g.
     * hundreths of a percent) for the loan, that must be repaid pro-rata by the borrower at the conclusion of the loan
     * or risk seizure of their nft collateral. Note if the type of the loan is fixed then this value  is not used and
     * is irrelevant so it should be set to 0.
     * - loanAdminFeeInBasisPoints: The percent (measured in basis points) of the interest earned that will be
     * taken as a fee by the contract admins when the loan is repaid. The fee is stored in the loan struct to prevent an
     * attack where the contract admins could adjust the fee right before a loan is repaid, and take all of the interest
     * earned.
     * @param _signature - The signature structure containing:
     * - signer: The address of the signer. The borrower for `acceptOffer` the lender for `acceptListing`.
     * - nonce: The nonce referred here is not the same as an Ethereum account's nonce.
     * We are referring instead to a nonce that is used by the lender or the borrower when they are first signing
     * off-chain NFTfi orders. These nonce can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     *   - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     *   - Second, it allows a user to cancel an off-chain order by calling
     * NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the nonce as used and prevents any future loan from
     * using the user's off-chain order that contains that nonce.
     * - expiry: Date when the signature expires
     * - signature: The ECDSA signature of the lender, obtained off-chain ahead of time, signing the following
     * combination of parameters:
     *   - offer.loanERC20Denomination
     *   - offer.loanPrincipalAmount
     *   - offer.maximumRepaymentAmount
     *   - offer.nftCollateralContract
     *   - offer.nftCollateralId
     *   - offer.referrer
     *   - offer.loanDuration
     *   - offer.loanAdminFeeInBasisPoints
     *   - signature.signer,
     *   - signature.nonce,
     *   - signature.expiry,
     *   - address of this contract
     *   - chainId
     */
    function isValidLenderSignature(LoanData.Offer memory _offer, LoanData.Signature memory _signature)
        external
        view
        returns (bool)
    {
        return isValidLenderSignature(_offer, _signature, address(this));
    }

    /**
     * @dev This function overload the previous function to allow the caller to specify the address of the contract
     *
     */
    function isValidLenderSignature(
        LoanData.Offer memory _offer,
        LoanData.Signature memory _signature,
        address _loanContract
    ) public view returns (bool) {
        require(block.timestamp <= _signature.expiry, "Lender Signature has expired");
        require(_loanContract != address(0), "Loan is zero address");
        if (_signature.signer == address(0)) {
            return false;
        } else {
            bytes32 message = keccak256(
                abi.encodePacked(getEncodedOffer(_offer), getEncodedSignature(_signature), _loanContract, getChainID())
            );

            return
                SignatureChecker.isValidSignatureNow(
                    _signature.signer,
                    ECDSA.toEthSignedMessageHash(message),
                    _signature.signature
                );
        }
    }

    /**
     * @notice This function is when the borrower accepts a lender's offer, to validate the lender's signature that the
     * lender provided off-chain to verify that it did indeed made such offer.
     *
     * @param _offer - The offer struct containing:
     * - loanERC20Denomination: The address of the ERC20 contract of the currency being used as principal/interest
     * for this loan.
     * - loanPrincipalAmount: The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * - maximumRepaymentAmount: The maximum amount of money that the borrower would be required to retrieve their
     * collateral, measured in the smallest units of the ERC20 currency used for the loan. The borrower will always have
     * to pay this amount to retrieve their collateral, regardless of whether they repay early.
     * - nftCollateralContract: The address of the ERC721 contract of the NFT collateral.
     * - nftCollateralId: The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * - referrer: The address of the referrer who found the lender matching the listing, Zero address to signal
     * this there is no referrer.
     * - loanDuration: The amount of time (measured in seconds) that can elapse before the lender can liquidate the
     * loan and seize the underlying collateral NFT.
     * - loanInterestRateForDurationInBasisPoints: This is the interest rate (measured in basis points, e.g.
     * hundreths of a percent) for the loan, that must be repaid pro-rata by the borrower at the conclusion of the loan
     * or risk seizure of their nft collateral. Note if the type of the loan is fixed then this value  is not used and
     * is irrelevant so it should be set to 0.
     * - loanAdminFeeInBasisPoints: The percent (measured in basis points) of the interest earned that will be
     * taken as a fee by the contract admins when the loan is repaid. The fee is stored in the loan struct to prevent an
     * attack where the contract admins could adjust the fee right before a loan is repaid, and take all of the interest
     * earned.
     * @param _bundleElements - the lists of erc721-20-1155 tokens that are to be bundled
     * @param _signature - The signature structure containing:
     * - signer: The address of the signer. The borrower for `acceptOffer` the lender for `acceptListing`.
     * - nonce: The nonce referred here is not the same as an Ethereum account's nonce.
     * We are referring instead to a nonce that is used by the lender or the borrower when they are first signing
     * off-chain NFTfi orders. These nonce can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     *   - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     *   - Second, it allows a user to cancel an off-chain order by calling
     * NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the nonce as used and prevents any future loan from
     * using the user's off-chain order that contains that nonce.
     * - expiry: Date when the signature expires
     * - signature: The ECDSA signature of the lender, obtained off-chain ahead of time, signing the following
     * combination of parameters:
     *   - offer.loanERC20Denomination
     *   - offer.loanPrincipalAmount
     *   - offer.maximumRepaymentAmount
     *   - offer.nftCollateralContract
     *   - offer.nftCollateralId
     *   - offer.referrer
     *   - offer.loanDuration
     *   - offer.loanAdminFeeInBasisPoints
     *   - bundleElements
     *   - signature.signer,
     *   - signature.nonce,
     *   - signature.expiry,
     *   - address of this contract
     *   - chainId
     */
    function isValidLenderSignatureBundle(
        LoanData.Offer memory _offer,
        IBundleBuilder.BundleElements memory _bundleElements,
        LoanData.Signature memory _signature
    ) external view returns (bool) {
        return isValidLenderSignatureBundle(_offer, _bundleElements, _signature, address(this));
    }

    /**
     * @dev This function overload the previous function to allow the caller to specify the address of the contract
     *
     */
    function isValidLenderSignatureBundle(
        LoanData.Offer memory _offer,
        IBundleBuilder.BundleElements memory _bundleElements,
        LoanData.Signature memory _signature,
        address _loanContract
    ) public view returns (bool) {
        require(block.timestamp <= _signature.expiry, "Lender Signature has expired");
        require(_loanContract != address(0), "Loan is zero address");
        if (_signature.signer == address(0)) {
            return false;
        } else {
            bytes32 message = keccak256(
                abi.encodePacked(
                    getEncodedOffer(_offer),
                    abi.encode(_bundleElements),
                    getEncodedSignature(_signature),
                    _loanContract,
                    getChainID()
                )
            );

            return
                SignatureChecker.isValidSignatureNow(
                    _signature.signer,
                    ECDSA.toEthSignedMessageHash(message),
                    _signature.signature
                );
        }
    }

    /**
     * @notice This function is called in renegotiateLoan() to validate the lender's signature that the lender provided
     * off-chain to verify that they did indeed want to agree to this loan renegotiation according to these terms.
     *
     * @param _loanId - The unique identifier for the loan to be renegotiated
     * @param _newLoanDuration - The new amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param _newMaximumRepaymentAmount - The new maximum amount of money that the borrower would be required to
     * retrieve their collateral, measured in the smallest units of the ERC20 currency used for the loan. The
     * borrower will always have to pay this amount to retrieve their collateral, regardless of whether they repay
     * early.
     * @param _renegotiationFee Agreed upon fee in ether that borrower pays for the lender for the renegitiation
     * @param _signature - The signature structure containing:
     * - signer: The address of the signer. The borrower for `acceptOffer` the lender for `acceptListing`.
     * - nonce: The nonce referred here is not the same as an Ethereum account's nonce.
     * We are referring instead to a nonce that is used by the lender or the borrower when they are first signing
     * off-chain NFTfi orders. These nonce can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     * - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     * - Second, it allows a user to cancel an off-chain order by calling NFTfi.cancelLoanCommitmentBeforeLoanHasBegun()
     * , which marks the nonce as used and prevents any future loan from using the user's off-chain order that contains
     * that nonce.
     * - expiry - The date when the renegotiation offer expires
     * - lenderSignature - The ECDSA signature of the lender, obtained off-chain ahead of time, signing the
     * following combination of parameters:
     * - _loanId
     * - _newLoanDuration
     * - _newMaximumRepaymentAmount
     * - _lender
     * - _lenderNonce
     * - _expiry
     * - address of this contract
     * - chainId
     */
    function isValidLenderRenegotiationSignature(
        uint256 _loanId,
        uint32 _newLoanDuration,
        uint256 _newMaximumRepaymentAmount,
        uint256 _renegotiationFee,
        LoanData.Signature memory _signature
    ) external view returns (bool) {
        return
            isValidLenderRenegotiationSignature(
                _loanId,
                _newLoanDuration,
                _newMaximumRepaymentAmount,
                _renegotiationFee,
                _signature,
                address(this)
            );
    }

    /**
     * @dev This function overload the previous function to allow the caller to specify the address of the contract
     *
     */
    function isValidLenderRenegotiationSignature(
        uint256 _loanId,
        uint32 _newLoanDuration,
        uint256 _newMaximumRepaymentAmount,
        uint256 _renegotiationFee,
        LoanData.Signature memory _signature,
        address _loanContract
    ) public view returns (bool) {
        require(block.timestamp <= _signature.expiry, "Renegotiation Signature has expired");
        require(_loanContract != address(0), "Loan is zero address");
        if (_signature.signer == address(0)) {
            return false;
        } else {
            bytes32 message = keccak256(
                abi.encodePacked(
                    _loanId,
                    _newLoanDuration,
                    _newMaximumRepaymentAmount,
                    _renegotiationFee,
                    getEncodedSignature(_signature),
                    _loanContract,
                    getChainID()
                )
            );

            return
                SignatureChecker.isValidSignatureNow(
                    _signature.signer,
                    ECDSA.toEthSignedMessageHash(message),
                    _signature.signature
                );
        }
    }

    /**
     * @dev We need this to avoid stack too deep errors.
     */
    function getEncodedListing(LoanData.ListingTerms memory _listingTerms) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                _listingTerms.loanERC20Denomination,
                _listingTerms.minLoanPrincipalAmount,
                _listingTerms.maxLoanPrincipalAmount,
                _listingTerms.nftCollateralContract,
                _listingTerms.nftCollateralId,
                _listingTerms.revenueSharePartner,
                _listingTerms.minLoanDuration,
                _listingTerms.maxLoanDuration,
                _listingTerms.maxInterestRateForDurationInBasisPoints,
                _listingTerms.referralFeeInBasisPoints
            );
    }

    /**
     * @dev We need this to avoid stack too deep errors.
     */
    function getEncodedOffer(LoanData.Offer memory _offer) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                _offer.loanERC20Denomination,
                _offer.loanPrincipalAmount,
                _offer.maximumRepaymentAmount,
                _offer.nftCollateralContract,
                _offer.nftCollateralId,
                _offer.referrer,
                _offer.loanDuration,
                _offer.loanAdminFeeInBasisPoints
            );
    }

    /**
     * @dev We need this to avoid stack too deep errors.
     */
    function getEncodedSignature(LoanData.Signature memory _signature) internal pure returns (bytes memory) {
        return abi.encodePacked(_signature.signer, _signature.nonce, _signature.expiry);
    }
}

// contracts/interfaces/ILoanCore.sol

interface ILoanCore {

    // ================ Data Types =================

    struct AffiliateSplit {
        address affiliate;
        uint96 splitBps;
    }

    struct NoteReceipt {
        address token;
        uint256 amount;
    }

    // ================ Events =================

    event LoanStarted(uint256 loanId, address lender, address borrower);
    event LoanRepaid(uint256 loanId);
    event ForceRepay(uint256 loanId);
    event LoanRolledOver(uint256 oldLoanId, uint256 newLoanId);
    event LoanClaimed(uint256 loanId);
    event NoteRedeemed(address indexed token, address indexed caller, address indexed to, uint256 tokenId, uint256 amount);
    event NonceUsed(address indexed user, uint160 nonce);

    event FeesWithdrawn(address indexed token, address indexed caller, address indexed to, uint256 amount);
    event AffiliateSet(bytes32 indexed code, address indexed affiliate, uint96 splitBps);

    // ============== Lifecycle Operations ==============

    function startLoan(
        address lender,
        address borrower,
        LoanLibrary.LoanTerms calldata terms,
        uint256 _amountFromLender,
        uint256 _amountToBorrower,
        LoanLibrary.FeeSnapshot calldata feeSnapshot
    ) external returns (uint256 loanId);

    function repay(
        uint256 loanId,
        address payer,
        uint256 _amountFromPayer,
        uint256 _amountToLender
    ) external;

    function forceRepay(
        uint256 loanId,
        address payer,
        uint256 _amountFromPayer,
        uint256 _amountToLender
    ) external;

    function claim(
        uint256 loanId,
        uint256 _amountFromLender
    ) external;

    function redeemNote(
        uint256 loanId,
        uint256 _amountFromLender,
        address to
    ) external;

    function rollover(
        uint256 oldLoanId,
        address borrower,
        address lender,
        LoanLibrary.LoanTerms calldata terms,
        uint256 _settledAmount,
        uint256 _amountToOldLender,
        uint256 _amountToLender,
        uint256 _amountToBorrower
    ) external returns (uint256 newLoanId);

    // ============== Nonce Management ==============

    function consumeNonce(address user, uint160 nonce) external;

    function cancelNonce(uint160 nonce) external;

    // ============== Fee Management ==============

    function withdraw(address token, uint256 amount, address to) external;

    function withdrawProtocolFees(address token, address to) external;

    // ============== Admin Operations ==============

    function setAffiliateSplits(bytes32[] calldata codes, AffiliateSplit[] calldata splits) external;

    // ============== View Functions ==============

    function getLoan(uint256 loanId) external view returns (LoanLibrary.LoanData calldata loanData);

    function getNoteReceipt(uint256 loanId) external view returns (address token, uint256 amount);

    function isNonceUsed(address user, uint160 nonce) external view returns (bool);

    function borrowerNote() external view returns (IPromissoryNote);

    function lenderNote() external view returns (IPromissoryNote);

}

// contracts/v2-migration/v2-contracts/v2-interfaces/ILoanCoreV2.sol

interface ILoanCoreV2 {
    // ================ Events =================

    event LoanCreated(LoanLibraryV2.LoanTerms terms, uint256 loanId);
    event LoanStarted(uint256 loanId, address lender, address borrower);
    event LoanRepaid(uint256 loanId);
    event LoanRolledOver(uint256 oldLoanId, uint256 newLoanId);
    event InstallmentPaymentReceived(uint256 loanId, uint256 repaidAmount, uint256 remBalance);
    event LoanClaimed(uint256 loanId);
    event FeesClaimed(address token, address to, uint256 amount);
    event SetFeeController(address feeController);
    event NonceUsed(address indexed user, uint160 nonce);

    // ============== Lifecycle Operations ==============

    function startLoan(
        address lender,
        address borrower,
        LoanLibraryV2.LoanTerms calldata terms
    ) external returns (uint256 loanId);

    function repay(uint256 loanId) external;

    function repayPart(
        uint256 _loanId,
        uint256 _currentMissedPayments,
        uint256 _paymentToPrincipal,
        uint256 _paymentToInterest,
        uint256 _paymentToLateFees,
        address _caller
    ) external;

    function claim(uint256 loanId, uint256 currentInstallmentPeriod) external;

    function rollover(
        uint256 oldLoanId,
        address borrower,
        address lender,
        LoanLibraryV2.LoanTerms calldata terms,
        uint256 _settledAmount,
        uint256 _amountToOldLender,
        uint256 _amountToLender,
        uint256 _amountToBorrower
    ) external returns (uint256 newLoanId);

    // ============== Nonce Management ==============

    function consumeNonce(address user, uint160 nonce) external;

    function cancelNonce(uint160 nonce) external;

    // ============== View Functions ==============

    function getLoan(uint256 loanId) external view returns (LoanLibraryV2.LoanData calldata loanData);

    function isNonceUsed(address user, uint160 nonce) external view returns (bool);

    function borrowerNote() external returns (IPromissoryNoteV2);

    function lenderNote() external returns (IPromissoryNoteV2);

    function feeController() external returns (IFeeControllerV2);
}

// contracts/interfaces/ILP1Migration.sol

interface ILP1Migration {

}

// contracts/external/lp-1/loans/direct/loanTypes/LoanChecksAndCalculations.sol

/**
 * @title  LoanChecksAndCalculations
 * @author NFTfi
 * @notice Helper library for LoanBase
 */
library LoanChecksAndCalculations {
    uint16 private constant HUNDRED_PERCENT = 10000;

    /**
     * @dev Function that performs some validation checks before trying to repay a loan
     *
     * @param _loanId - The id of the loan being repaid
     */
    function payBackChecks(uint32 _loanId, INftfiHub _hub) external view {
        checkLoanIdValidity(_loanId, _hub);
        // Sanity check that payBackLoan() and liquidateOverdueLoan() have never been called on this loanId.
        // Depending on how the rest of the code turns out, this check may be unnecessary.
        require(!IDirectLoanBase(address(this)).loanRepaidOrLiquidated(_loanId), "Loan already repaid/liquidated");

        // Fetch loan details from storage, but store them in memory for the sake of saving gas.
        (, , , , uint32 loanDuration, , , , uint64 loanStartTime, , ) = IDirectLoanBase(address(this)).loanIdToLoan(
            _loanId
        );

        // When a loan exceeds the loan term, it is expired. At this stage the Lender can call Liquidate Loan to resolve
        // the loan.
        require(block.timestamp <= (uint256(loanStartTime) + uint256(loanDuration)), "Loan is expired");
    }

    function checkLoanIdValidity(uint32 _loanId, INftfiHub _hub) public view {
        require(
            IDirectLoanCoordinator(_hub.getContract(IDirectLoanBase(address(this)).LOAN_COORDINATOR())).isValidLoanId(
                _loanId,
                address(this)
            ),
            "invalid loanId"
        );
    }

    /**
     * @dev Function that the partner is permitted and returns its shared percent.
     *
     * @param _revenueSharePartner - Partner's address
     *
     * @return The revenue share percent for the partner.
     */
    function getRevenueSharePercent(address _revenueSharePartner, INftfiHub _hub) external view returns (uint16) {
        // return soon if no partner is set to avoid a public call
        if (_revenueSharePartner == address(0)) {
            return 0;
        }

        uint16 revenueSharePercent = IPermittedPartners(_hub.getContract(ContractKeys.PERMITTED_PARTNERS))
        .getPartnerPermit(_revenueSharePartner);

        return revenueSharePercent;
    }

    /**
     * @dev Performs some validation checks before trying to renegotiate a loan.
     * Needed to avoid stack too deep.
     *
     * @param _loan - The main Loan Terms struct.
     * @param _loanId - The unique identifier for the loan to be renegotiated
     * @param _newLoanDuration - The new amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param _newMaximumRepaymentAmount - The new maximum amount of money that the borrower would be required to
     * retrieve their collateral, measured in the smallest units of the ERC20 currency used for the loan. The
     * borrower will always have to pay this amount to retrieve their collateral, regardless of whether they repay
     * early.
     * @param _lenderNonce - The nonce referred to here is not the same as an Ethereum account's nonce. We are
     * referring instead to nonces that are used by both the lender and the borrower when they are first signing
     * off-chain NFTfi orders. These nonces can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     * - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     * - Second, it allows a user to cancel an off-chain order by calling NFTfi.cancelLoanCommitmentBeforeLoanHasBegun()
     , which marks the nonce as used and prevents any future loan from using the user's off-chain order that contains
     * that nonce.
     * @return Borrower and Lender addresses
     */
    function renegotiationChecks(
        LoanData.LoanTerms memory _loan,
        uint32 _loanId,
        uint32 _newLoanDuration,
        uint256 _newMaximumRepaymentAmount,
        uint256 _lenderNonce,
        INftfiHub _hub
    ) external view returns (address, address) {
        checkLoanIdValidity(_loanId, _hub);
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(
            _hub.getContract(IDirectLoanBase(address(this)).LOAN_COORDINATOR())
        );
        uint256 smartNftId = loanCoordinator.getLoanData(_loanId).smartNftId;

        address borrower;

        if (_loan.borrower != address(0)) {
            borrower = _loan.borrower;
        } else {
            borrower = IERC721(loanCoordinator.obligationReceiptToken()).ownerOf(smartNftId);
        }

        require(msg.sender == borrower, "Only borrower can initiate");
        require(block.timestamp <= (uint256(_loan.loanStartTime) + _newLoanDuration), "New duration already expired");
        require(
            uint256(_newLoanDuration) <= IDirectLoanBase(address(this)).maximumLoanDuration(),
            "New duration exceeds maximum loan duration"
        );
        require(!IDirectLoanBase(address(this)).loanRepaidOrLiquidated(_loanId), "Loan already repaid/liquidated");
        require(
            _newMaximumRepaymentAmount >= _loan.loanPrincipalAmount,
            "Negative interest rate loans are not allowed."
        );

        // Fetch current owner of loan promissory note.
        address lender = IERC721(loanCoordinator.promissoryNoteToken()).ownerOf(smartNftId);

        require(
            !IDirectLoanBase(address(this)).getWhetherNonceHasBeenUsedForUser(lender, _lenderNonce),
            "Lender nonce invalid"
        );

        return (borrower, lender);
    }

    /**
     * @dev Performs some validation checks over loan parameters when accepting a listing
     *
     */
    function bindingTermsSanityChecks(LoanData.ListingTerms memory _listingTerms, LoanData.Offer memory _offer)
        external
        pure
    {
        // offer vs listing validations
        require(_offer.loanERC20Denomination == _listingTerms.loanERC20Denomination, "Invalid loanERC20Denomination");
        require(
            _offer.loanPrincipalAmount >= _listingTerms.minLoanPrincipalAmount &&
                _offer.loanPrincipalAmount <= _listingTerms.maxLoanPrincipalAmount,
            "Invalid loanPrincipalAmount"
        );
        uint256 maxRepaymentLimit = _offer.loanPrincipalAmount +
            (_offer.loanPrincipalAmount * _listingTerms.maxInterestRateForDurationInBasisPoints) /
            HUNDRED_PERCENT;
        require(_offer.maximumRepaymentAmount <= maxRepaymentLimit, "maxInterestRateForDurationInBasisPoints violated");

        require(
            _offer.loanDuration >= _listingTerms.minLoanDuration &&
                _offer.loanDuration <= _listingTerms.maxLoanDuration,
            "Invalid loanDuration"
        );
    }

    /**
     * @notice A convenience function computing the revenue share taken from the admin fee to transferr to the permitted
     * partner.
     *
     * @param _adminFee - The quantity of ERC20 currency (measured in smalled units of that ERC20 currency) that is due
     * as an admin fee.
     * @param _revenueShareInBasisPoints - The percent (measured in basis points) of the admin fee amount that will be
     * taken as a revenue share for a the partner, at the moment the loan is begun.
     *
     * @return The quantity of ERC20 currency (measured in smalled units of that ERC20 currency) that should be sent to
     * the `revenueSharePartner`.
     */
    function computeRevenueShare(uint256 _adminFee, uint256 _revenueShareInBasisPoints)
        external
        pure
        returns (uint256)
    {
        return (_adminFee * _revenueShareInBasisPoints) / HUNDRED_PERCENT;
    }

    /**
     * @notice A convenience function computing the adminFee taken from a specified quantity of interest.
     *
     * @param _interestDue - The amount of interest due, measured in the smallest quantity of the ERC20 currency being
     * used to pay the interest.
     * @param _adminFeeInBasisPoints - The percent (measured in basis points) of the interest earned that will be taken
     * as a fee by the contract admins when the loan is repaid. The fee is stored in the loan struct to prevent an
     * attack where the contract admins could adjust the fee right before a loan is repaid, and take all of the interest
     * earned.
     *
     * @return The quantity of ERC20 currency (measured in smalled units of that ERC20 currency) that is due as an admin
     * fee.
     */
    function computeAdminFee(uint256 _interestDue, uint256 _adminFeeInBasisPoints) external pure returns (uint256) {
        return (_interestDue * _adminFeeInBasisPoints) / HUNDRED_PERCENT;
    }

    /**
     * @notice A convenience function computing the referral fee taken from the loan principal amount to transferr to
     * the referrer.
     *
     * @param _loanPrincipalAmount - The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param _referralFeeInBasisPoints - The percent (measured in basis points) of the loan principal amount that will
     * be taken as a fee to pay to the referrer, 0 if the lender is not paying referral fee.
     * @param _referrer - The address of the referrer who found the lender matching the listing, Zero address to signal
     * that there is no referrer.
     *
     * @return The quantity of ERC20 currency (measured in smalled units of that ERC20 currency) that should be sent to
     * the referrer.
     */
    function computeReferralFee(
        uint256 _loanPrincipalAmount,
        uint256 _referralFeeInBasisPoints,
        address _referrer
    ) external pure returns (uint256) {
        if (_referralFeeInBasisPoints == 0 || _referrer == address(0)) {
            return 0;
        }
        return (_loanPrincipalAmount * _referralFeeInBasisPoints) / HUNDRED_PERCENT;
    }
}

// contracts/external/lp-1/loans/direct/loanTypes/LoanAirdropUtils.sol

/**
 * @title  LoanAirdropUtils
 * @author NFTfi
 * @notice Helper library for LoanBase
 */
library LoanAirdropUtils {
    /**
     * @notice This event is fired whenever a flashloan is initiated to pull an airdrop
     *
     * @param  loanId - A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param  borrower - The address of the borrower.
     * @param  nftCollateralId - The ID within the AirdropReceiver for the NFT being used as collateral for this
     * loan.
     * @param  nftCollateralContract - The ERC721 contract of the NFT collateral
     * @param target - address of the airdropping contract
     * @param data - function selector to be called
     */
    event AirdropPulledFlashloan(
        uint256 indexed loanId,
        address indexed borrower,
        uint256 nftCollateralId,
        address nftCollateralContract,
        address target,
        bytes data
    );

    /**
     * @notice This event is fired whenever the collateral gets wrapped in an airdrop receiver
     *
     * @param  loanId - A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param  borrower - The address of the borrower.
     * @param  nftCollateralId - The ID within the AirdropReceiver for the NFT being used as collateral for this
     * loan.
     * @param  nftCollateralContract - The contract of the NFT collateral
     * @param receiverId - id of the created AirdropReceiver, takes the place of nftCollateralId on the loan
     * @param receiverInstance - address of the created AirdropReceiver
     */
    event CollateralWrapped(
        uint256 indexed loanId,
        address indexed borrower,
        uint256 nftCollateralId,
        address nftCollateralContract,
        uint256 receiverId,
        address receiverInstance
    );

    function pullAirdrop(
        uint32 _loanId,
        LoanData.LoanTerms memory _loan,
        address _target,
        bytes calldata _data,
        address _nftAirdrop,
        uint256 _nftAirdropId,
        bool _is1155,
        uint256 _nftAirdropAmount,
        INftfiHub _hub
    ) external {
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(
            _hub.getContract(IDirectLoanBase(address(this)).LOAN_COORDINATOR())
        );

        address borrower;

        // scoped to aviod stack too deep
        {
            IDirectLoanCoordinator.Loan memory loanCoordinatorData = loanCoordinator.getLoanData(_loanId);
            uint256 smartNftId = loanCoordinatorData.smartNftId;
            if (_loan.borrower != address(0)) {
                borrower = _loan.borrower;
            } else {
                borrower = IERC721(loanCoordinator.obligationReceiptToken()).ownerOf(smartNftId);
            }
        }

        require(msg.sender == borrower, "Only borrower can airdrop");

        {
            IAirdropFlashLoan airdropFlashLoan = IAirdropFlashLoan(_hub.getContract(ContractKeys.AIRDROP_FLASH_LOAN));

            _transferNFT(_loan, address(this), address(airdropFlashLoan));

            airdropFlashLoan.pullAirdrop(
                _loan.nftCollateralContract,
                _loan.nftCollateralId,
                _loan.nftCollateralWrapper,
                _target,
                _data,
                _nftAirdrop,
                _nftAirdropId,
                _is1155,
                _nftAirdropAmount,
                borrower
            );
        }

        // revert if the collateral hasn't been transferred back before it ends
        require(
            INftWrapper(_loan.nftCollateralWrapper).isOwner(
                address(this),
                _loan.nftCollateralContract,
                _loan.nftCollateralId
            ),
            "Collateral should be returned"
        );

        emit AirdropPulledFlashloan(
            _loanId,
            borrower,
            _loan.nftCollateralId,
            _loan.nftCollateralContract,
            _target,
            _data
        );
    }

    function wrapCollateral(
        uint32 _loanId,
        LoanData.LoanTerms storage _loan,
        INftfiHub _hub
    ) external returns (address instance, uint256 receiverId) {
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(
            _hub.getContract(IDirectLoanBase(address(this)).LOAN_COORDINATOR())
        );
        // Fetch the current lender of the promissory note corresponding to this overdue loan.
        IDirectLoanCoordinator.Loan memory loanCoordinatorData = loanCoordinator.getLoanData(_loanId);
        uint256 smartNftId = loanCoordinatorData.smartNftId;

        address borrower;

        if (_loan.borrower != address(0)) {
            borrower = _loan.borrower;
        } else {
            borrower = IERC721(loanCoordinator.obligationReceiptToken()).ownerOf(smartNftId);
        }

        require(msg.sender == borrower, "Only borrower can wrapp");

        IAirdropReceiverFactory factory = IAirdropReceiverFactory(_hub.getContract(ContractKeys.AIRDROP_FACTORY));
        (instance, receiverId) = factory.createAirdropReceiver(address(this));

        // transfer collateral to airdrop receiver wrapper
        _transferNFTtoAirdropReceiver(_loan, instance, borrower);

        emit CollateralWrapped(
            _loanId,
            borrower,
            _loan.nftCollateralId,
            _loan.nftCollateralContract,
            receiverId,
            instance
        );

        // set the receiver as the new collateral
        _loan.nftCollateralContract = instance;
        _loan.nftCollateralId = receiverId;
    }

    /**
     * @dev Transfers several types of NFTs using a wrapper that knows how to handle each case.
     *
     * @param _loan -
     * @param _sender - Current owner of the NFT
     * @param _recipient - Recipient of the transfer
     */
    function _transferNFT(
        LoanData.LoanTerms memory _loan,
        address _sender,
        address _recipient
    ) internal {
        Address.functionDelegateCall(
            _loan.nftCollateralWrapper,
            abi.encodeWithSelector(
                INftWrapper(_loan.nftCollateralWrapper).transferNFT.selector,
                _sender,
                _recipient,
                _loan.nftCollateralContract,
                _loan.nftCollateralId
            ),
            "NFT not successfully transferred"
        );
    }

    /**
     * @dev Transfers several types of NFTs to an airdrop receiver with an airdrop beneficiary
     * address attached as supplementing data using a wrapper that knows how to handle each case.
     *
     * @param _loan -
     * @param _airdropReceiverInstance - Recipient of the transfer
     * @param _airdropBeneficiary - Beneficiary of the future airdops
     */
    function _transferNFTtoAirdropReceiver(
        LoanData.LoanTerms memory _loan,
        address _airdropReceiverInstance,
        address _airdropBeneficiary
    ) internal {
        Address.functionDelegateCall(
            _loan.nftCollateralWrapper,
            abi.encodeWithSelector(
                INftWrapper(_loan.nftCollateralWrapper).wrapAirdropReceiver.selector,
                _airdropReceiverInstance,
                _loan.nftCollateralContract,
                _loan.nftCollateralId,
                _airdropBeneficiary
            ),
            "NFT was not successfully migrated"
        );
    }
}

// contracts/interfaces/IMigrationBase.sol

interface IMigrationBase is IFlashLoanRecipient {
    event PausedStateChanged(bool isPaused);

    function flushToken(IERC20 token, address to) external;

    function pause(bool _pause) external;
}

// contracts/external/lp-1/loans/direct/loanTypes/DirectLoanBaseMinimal.sol

/**
 * @title  DirectLoanBase
 * @author NFTfi
 * @notice Main contract for NFTfi Direct Loans Type. This contract manages the ability to create NFT-backed
 * peer-to-peer loans.
 *
 * There are two ways to commence an NFT-backed loan:
 *
 * a. The borrower accepts a lender's offer by calling `acceptOffer`.
 *   1. the borrower calls nftContract.approveAll(NFTfi), approving the NFTfi contract to move their NFT's on their
 * be1alf.
 *   2. the lender calls erc20Contract.approve(NFTfi), allowing NFTfi to move the lender's ERC20 tokens on their
 * behalf.
 *   3. the lender signs an off-chain message, proposing its offer terms.
 *   4. the borrower calls `acceptOffer` to accept these terms and enter into the loan. The NFT is stored in
 * the contract, the borrower receives the loan principal in the specified ERC20 currency, the lender receives an
 * NFTfi promissory note (in ERC721 form) that represents the rights to either the principal-plus-interest, or the
 * underlying NFT collateral if the borrower does not pay back in time, and the borrower receives obligation receipt
 * (in ERC721 form) that gives them the right to pay back the loan and get the collateral back.
 *
 * b. The lender accepts a borrowe's binding terms by calling `acceptListing`.
 *   1. the borrower calls nftContract.approveAll(NFTfi), approving the NFTfi contract to move their NFT's on their
 * be1alf.
 *   2. the lender calls erc20Contract.approve(NFTfi), allowing NFTfi to move the lender's ERC20 tokens on their
 * behalf.
 *   3. the borrower signs an off-chain message, proposing its binding terms.
 *   4. the lender calls `acceptListing` with an offer matching the binding terms and enter into the loan. The NFT is
 * stored in the contract, the borrower receives the loan principal in the specified ERC20 currency, the lender
 * receives an NFTfi promissory note (in ERC721 form) that represents the rights to either the principal-plus-interest,
 * or the underlying NFT collateral if the borrower does not pay back in time, and the borrower receives obligation
 * receipt (in ERC721 form) that gives them the right to pay back the loan and get the collateral back.
 *
 * The lender can freely transfer and trade this ERC721 promissory note as they wish, with the knowledge that
 * transferring the ERC721 promissory note tranfsers the rights to principal-plus-interest and/or collateral, and that
 * they will no longer have a claim on the loan. The ERC721 promissory note itself represents that claim.
 *
 * The borrower can freely transfer and trade this ERC721 obligaiton receipt as they wish, with the knowledge that
 * transferring the ERC721 obligaiton receipt tranfsers the rights right to pay back the loan and get the collateral
 * back.
 *
 * A loan may end in one of two ways:
 * - First, a borrower may call NFTfi.payBackLoan() and pay back the loan plus interest at any time, in which case they
 * receive their NFT back in the same transaction.
 * - Second, if the loan's duration has passed and the loan has not been paid back yet, a lender can call
 * NFTfi.liquidateOverdueLoan(), in which case they receive the underlying NFT collateral and forfeit the rights to the
 * principal-plus-interest, which the borrower now keeps.
 *
 *
 * If the loan was created as a ProRated type loan (pro-rata interest loan), then the user only pays the principal plus
 * pro-rata interest if repaid early.
 * However, if the loan was was created as a Fixed type loan (agreed to be a fixed-repayment loan), then the borrower
 * pays the maximumRepaymentAmount regardless of whether they repay early or not.
 *
 */
abstract contract DirectLoanBaseMinimal is IDirectLoanBase, IPermittedERC20s, BaseLoan, NftReceiver, LoanData {
    using SafeERC20 for IERC20;

    /* ******* */
    /* STORAGE */
    /* ******* */

    uint16 public constant HUNDRED_PERCENT = 10000;

    bytes32 public immutable override LOAN_COORDINATOR;

    /**
     * @notice The maximum duration of any loan started for this loan type, measured in seconds. This is both a
     * sanity-check for borrowers and an upper limit on how long admins will have to support v1 of this contract if they
     * eventually deprecate it, as well as a check to ensure that the loan duration never exceeds the space alotted for
     * it in the loan struct.
     */
    uint256 public override maximumLoanDuration = 53 weeks;

    /**
     * @notice The percentage of interest earned by lenders on this platform that is taken by the contract admin's as a
     * fee, measured in basis points (hundreths of a percent). The max allowed value is 10000.
     */
    uint16 public override adminFeeInBasisPoints = 25;

    /**
     * @notice A mapping from a loan's identifier to the loan's details, represted by the loan struct.
     */
    mapping(uint32 => LoanTerms) public override loanIdToLoan;
    mapping(uint32 => LoanExtras) public loanIdToLoanExtras;

    /**
     * @notice A mapping tracking whether a loan has either been repaid or liquidated. This prevents an attacker trying
     * to repay or liquidate the same loan twice.
     */
    mapping(uint32 => bool) public override loanRepaidOrLiquidated;

    /**
     * @dev keeps track of tokens being held as loan collateral, so we dont allow these
     * to be transferred with the aridrop draining functions
     */
    mapping(address => mapping(uint256 => uint256)) private _escrowTokens;

    /**
     * @notice A mapping that takes both a user's address and a loan nonce that was first used when signing an off-chain
     * order and checks whether that nonce has previously either been used for a loan, or has been pre-emptively
     * cancelled. The nonce referred to here is not the same as an Ethereum account's nonce. We are referring instead to
     * nonces that are used by both the lender and the borrower when they are first signing off-chain NFTfi orders.
     *
     * These nonces can be any uint256 value that the user has not previously used to sign an off-chain order. Each
     * nonce can be used at most once per user within NFTfi, regardless of whether they are the lender or the borrower
     * in that situation. This serves two purposes. First, it prevents replay attacks where an attacker would submit a
     * user's off-chain order more than once. Second, it allows a user to cancel an off-chain order by calling
     * NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the nonce as used and prevents any future loan from
     * using the user's off-chain order that contains that nonce.
     */
    mapping(address => mapping(uint256 => bool)) internal _nonceHasBeenUsedForUser;

    /**
     * @notice A mapping from an ERC20 currency address to whether that currency
     * is permitted to be used by this contract.
     */
    mapping(address => bool) private erc20Permits;

    INftfiHub public immutable hub;

    /* ****** */
    /* EVENTS */
    /* ****** */

    /**
     * @notice This event is fired whenever the admins change the percent of interest rates earned that they charge as a
     * fee. Note that newAdminFee can never exceed 10,000, since the fee is measured in basis points.
     *
     * @param  newAdminFee - The new admin fee measured in basis points. This is a percent of the interest paid upon a
     * loan's completion that go to the contract admins.
     */
    event AdminFeeUpdated(uint16 newAdminFee);

    /**
     * @notice This event is fired whenever the admins change the maximum duration of any loan started for this loan
     * type.
     *
     * @param  newMaximumLoanDuration - The new maximum duration.
     */
    event MaximumLoanDurationUpdated(uint256 newMaximumLoanDuration);

    /**
     * @notice This event is fired whenever a borrower begins a loan by calling NFTfi.beginLoan(), which can only occur
     * after both the lender and borrower have approved their ERC721 and ERC20 contracts to use NFTfi, and when they
     * both have signed off-chain messages that agree on the terms of the loan.
     *
     * @param  loanId - A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param  borrower - The address of the borrower.
     * @param  lender - The address of the lender. The lender can change their address by transferring the NFTfi ERC721
     * token that they received when the loan began.
     */
    event LoanStarted(
        uint32 indexed loanId,
        address indexed borrower,
        address indexed lender,
        LoanTerms loanTerms,
        LoanExtras loanExtras
    );

    /**
     * @notice This event is fired whenever a borrower successfully repays their loan, paying
     * principal-plus-interest-minus-fee to the lender in loanERC20Denomination, paying fee to owner in
     * loanERC20Denomination, and receiving their NFT collateral back.
     *
     * @param  loanId - A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param  borrower - The address of the borrower.
     * @param  lender - The address of the lender. The lender can change their address by transferring the NFTfi ERC721
     * token that they received when the loan began.
     * @param  loanPrincipalAmount - The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param  nftCollateralId - The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * @param  amountPaidToLender The amount of ERC20 that the borrower paid to the lender, measured in the smalled
     * units of loanERC20Denomination.
     * @param  adminFee The amount of interest paid to the contract admins, measured in the smalled units of
     * loanERC20Denomination and determined by adminFeeInBasisPoints. This amount never exceeds the amount of interest
     * earned.
     * @param  revenueShare The amount taken from admin fee amount shared with the partner.
     * @param  revenueSharePartner  - The address of the partner that will receive the revenue share.
     * @param  nftCollateralContract - The ERC721 contract of the NFT collateral
     * @param  loanERC20Denomination - The ERC20 contract of the currency being used as principal/interest for this
     * loan.
     */
    event LoanRepaid(
        uint32 indexed loanId,
        address indexed borrower,
        address indexed lender,
        uint256 loanPrincipalAmount,
        uint256 nftCollateralId,
        uint256 amountPaidToLender,
        uint256 adminFee,
        uint256 revenueShare,
        address revenueSharePartner,
        address nftCollateralContract,
        address loanERC20Denomination
    );

    /**
     * @notice This event is fired whenever a lender liquidates an outstanding loan that is owned to them that has
     * exceeded its duration. The lender receives the underlying NFT collateral, and the borrower no longer needs to
     * repay the loan principal-plus-interest.
     *
     * @param  loanId - A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param  borrower - The address of the borrower.
     * @param  lender - The address of the lender. The lender can change their address by transferring the NFTfi ERC721
     * token that they received when the loan began.
     * @param  loanPrincipalAmount - The original sum of money transferred from lender to borrower at the beginning of
     * the loan, measured in loanERC20Denomination's smallest units.
     * @param  nftCollateralId - The ID within the NFTCollateralContract for the NFT being used as collateral for this
     * loan. The NFT is stored within this contract during the duration of the loan.
     * @param  loanMaturityDate - The unix time (measured in seconds) that the loan became due and was eligible for
     * liquidation.
     * @param  loanLiquidationDate - The unix time (measured in seconds) that liquidation occurred.
     * @param  nftCollateralContract - The ERC721 contract of the NFT collateral
     */
    event LoanLiquidated(
        uint32 indexed loanId,
        address indexed borrower,
        address indexed lender,
        uint256 loanPrincipalAmount,
        uint256 nftCollateralId,
        uint256 loanMaturityDate,
        uint256 loanLiquidationDate,
        address nftCollateralContract
    );

    /**
     * @notice This event is fired when some of the terms of a loan are being renegotiated.
     *
     * @param loanId - The unique identifier for the loan to be renegotiated
     * @param newLoanDuration - The new amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param newMaximumRepaymentAmount - The new maximum amount of money that the borrower would be required to
     * retrieve their collateral, measured in the smallest units of the ERC20 currency used for the loan. The
     * borrower will always have to pay this amount to retrieve their collateral, regardless of whether they repay
     * early.
     * @param renegotiationFee Agreed upon fee in loan denomination that borrower pays for the lender for the
     * renegotiation, has to be paid with an ERC20 transfer loanERC20Denomination token, uses transfer from,
     * frontend will have to propmt an erc20 approve for this from the borrower to the lender
     * @param renegotiationAdminFee renegotiationFee admin portion based on determined by adminFeeInBasisPoints
     */
    event LoanRenegotiated(
        uint32 indexed loanId,
        address indexed borrower,
        address indexed lender,
        uint32 newLoanDuration,
        uint256 newMaximumRepaymentAmount,
        uint256 renegotiationFee,
        uint256 renegotiationAdminFee
    );

    /**
     * @notice This event is fired whenever the admin sets a ERC20 permit.
     *
     * @param erc20Contract - Address of the ERC20 contract.
     * @param isPermitted - Signals ERC20 permit.
     */
    event ERC20Permit(address indexed erc20Contract, bool isPermitted);

    /* *********** */
    /* CONSTRUCTOR */
    /* *********** */

    /**
     * @dev Sets `hub`
     *
     * @param _admin - Initial admin of this contract.
     * @param  _nftfiHub - NFTfiHub address
     * @param  _loanCoordinatorKey -
     * @param  _permittedErc20s -
     */
    constructor(
        address _admin,
        address _nftfiHub,
        bytes32 _loanCoordinatorKey,
        address[] memory _permittedErc20s
    ) BaseLoan(_admin) {
        hub = INftfiHub(_nftfiHub);
        LOAN_COORDINATOR = _loanCoordinatorKey;
        for (uint256 i = 0; i < _permittedErc20s.length; i++) {
            _setERC20Permit(_permittedErc20s[i], true);
        }
    }

    /* *************** */
    /* ADMIN FUNCTIONS */
    /* *************** */

    /**
     * @notice This function can be called by admins to change the maximumLoanDuration. Note that they can never change
     * maximumLoanDuration to be greater than UINT32_MAX, since that's the maximum space alotted for the duration in the
     * loan struct.
     *
     * @param _newMaximumLoanDuration - The new maximum loan duration, measured in seconds.
     */
    function updateMaximumLoanDuration(uint256 _newMaximumLoanDuration) external onlyOwner {
        require(_newMaximumLoanDuration <= uint256(type(uint32).max), "Loan duration overflow");
        maximumLoanDuration = _newMaximumLoanDuration;
        emit MaximumLoanDurationUpdated(_newMaximumLoanDuration);
    }

    /**
     * @notice This function can be called by admins to change the percent of interest rates earned that they charge as
     * a fee. Note that newAdminFee can never exceed 10,000, since the fee is measured in basis points.
     *
     * @param _newAdminFeeInBasisPoints - The new admin fee measured in basis points. This is a percent of the interest
     * paid upon a loan's completion that go to the contract admins.
     */
    function updateAdminFee(uint16 _newAdminFeeInBasisPoints) external onlyOwner {
        require(_newAdminFeeInBasisPoints <= HUNDRED_PERCENT, "basis points > 10000");
        adminFeeInBasisPoints = _newAdminFeeInBasisPoints;
        emit AdminFeeUpdated(_newAdminFeeInBasisPoints);
    }

    /**
     * @notice used by the owner account to be able to drain ERC20 tokens received as airdrops
     * for the locked  collateral NFT-s
     * @param _tokenAddress - address of the token contract for the token to be sent out
     * @param _receiver - receiver of the token
     */
    function drainERC20Airdrop(address _tokenAddress, address _receiver) external onlyOwner {
        IERC20 tokenContract = IERC20(_tokenAddress);
        uint256 amount = tokenContract.balanceOf(address(this));
        require(amount > 0, "no tokens owned");
        tokenContract.safeTransfer(_receiver, amount);
    }

    /**
     * @notice This function can be called by admins to change the permitted status of an ERC20 currency. This includes
     * both adding an ERC20 currency to the permitted list and removing it.
     *
     * @param _erc20 - The address of the ERC20 currency whose permit list status changed.
     * @param _permit - The new status of whether the currency is permitted or not.
     */
    function setERC20Permit(address _erc20, bool _permit) external onlyOwner {
        _setERC20Permit(_erc20, _permit);
    }

    /**
     * @notice This function can be called by admins to change the permitted status of a batch of ERC20 currency. This
     * includes both adding an ERC20 currency to the permitted list and removing it.
     *
     * @param _erc20s - The addresses of the ERC20 currencies whose permit list status changed.
     * @param _permits - The new statuses of whether the currency is permitted or not.
     */
    function setERC20Permits(address[] memory _erc20s, bool[] memory _permits) external onlyOwner {
        require(_erc20s.length == _permits.length, "setERC20Permits function information arity mismatch");

        for (uint256 i = 0; i < _erc20s.length; i++) {
            _setERC20Permit(_erc20s[i], _permits[i]);
        }
    }

    /**
     * @notice used by the owner account to be able to drain ERC721 tokens received as airdrops
     * for the locked  collateral NFT-s
     * @param _tokenAddress - address of the token contract for the token to be sent out
     * @param _tokenId - id token to be sent out
     * @param _receiver - receiver of the token
     */
    function drainERC721Airdrop(
        address _tokenAddress,
        uint256 _tokenId,
        address _receiver
    ) external onlyOwner {
        IERC721 tokenContract = IERC721(_tokenAddress);
        require(_escrowTokens[_tokenAddress][_tokenId] == 0, "token is collateral");
        require(tokenContract.ownerOf(_tokenId) == address(this), "nft not owned");
        tokenContract.safeTransferFrom(address(this), _receiver, _tokenId);
    }

    /**
     * @notice used by the owner account to be able to drain ERC1155 tokens received as airdrops
     * for the locked  collateral NFT-s
     * @param _tokenAddress - address of the token contract for the token to be sent out
     * @param _tokenId - id token to be sent out
     * @param _receiver - receiver of the token
     */
    function drainERC1155Airdrop(
        address _tokenAddress,
        uint256 _tokenId,
        address _receiver
    ) external onlyOwner {
        IERC1155 tokenContract = IERC1155(_tokenAddress);
        uint256 amount = tokenContract.balanceOf(address(this), _tokenId);
        require(_escrowTokens[_tokenAddress][_tokenId] == 0, "token is collateral");
        require(amount > 0, "no nfts owned");
        tokenContract.safeTransferFrom(address(this), _receiver, _tokenId, amount, "");
    }

    function mintObligationReceipt(uint32 _loanId) external nonReentrant {
        address borrower = loanIdToLoan[_loanId].borrower;
        require(msg.sender == borrower, "sender has to be borrower");

        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(hub.getContract(LOAN_COORDINATOR));
        loanCoordinator.mintObligationReceipt(_loanId, borrower);

        delete loanIdToLoan[_loanId].borrower;
    }

    /**
     * @dev makes possible to change loan duration and max repayment amount, loan duration even can be extended if
     * loan was expired but not liquidated.
     *
     * @param _loanId - The unique identifier for the loan to be renegotiated
     * @param _newLoanDuration - The new amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param _newMaximumRepaymentAmount - The new maximum amount of money that the borrower would be required to
     * retrieve their collateral, measured in the smallest units of the ERC20 currency used for the loan. The
     * borrower will always have to pay this amount to retrieve their collateral, regardless of whether they repay
     * early.
     * @param _renegotiationFee Agreed upon fee in ether that borrower pays for the lender for the renegitiation
     * @param _lenderNonce - The nonce referred to here is not the same as an Ethereum account's nonce. We are
     * referring instead to nonces that are used by both the lender and the borrower when they are first signing
     * off-chain NFTfi orders. These nonces can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     * - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     * - Second, it allows a user to cancel an off-chain order by calling NFTfi.cancelLoanCommitmentBeforeLoanHasBegun()
     * , which marks the nonce as used and prevents any future loan from using the user's off-chain order that contains
     * that nonce.
     * @param _expiry - The date when the renegotiation offer expires
     * @param _lenderSignature - The ECDSA signature of the lender, obtained off-chain ahead of time, signing the
     * following combination of parameters:
     * - _loanId
     * - _newLoanDuration
     * - _newMaximumRepaymentAmount
     * - _lender
     * - _expiry
     *  - address of this contract
     * - chainId
     */
    function renegotiateLoan(
        uint32 _loanId,
        uint32 _newLoanDuration,
        uint256 _newMaximumRepaymentAmount,
        uint256 _renegotiationFee,
        uint256 _lenderNonce,
        uint256 _expiry,
        bytes memory _lenderSignature
    ) external whenNotPaused nonReentrant {
        _renegotiateLoan(
            _loanId,
            _newLoanDuration,
            _newMaximumRepaymentAmount,
            _renegotiationFee,
            _lenderNonce,
            _expiry,
            _lenderSignature
        );
    }

    /**
     * @notice This function is called by a anyone to repay a loan. It can be called at any time after the loan has
     * begun and before loan expiry.. The caller will pay a pro-rata portion of their interest if the loan is paid off
     * early and the loan is pro-rated type, but the complete repayment amount if it is fixed type.
     * The the borrower (current owner of the obligation note) will get the collaterl NFT back.
     *
     * This function is purposefully not pausable in order to prevent an attack where the contract admin's pause the
     * contract and hold hostage the NFT's that are still within it.
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     */
    function payBackLoan(uint32 _loanId) external nonReentrant {
        LoanChecksAndCalculations.payBackChecks(_loanId, hub);
        (
            address borrower,
            address lender,
            LoanTerms memory loan,
            IDirectLoanCoordinator loanCoordinator
        ) = _getPartiesAndData(_loanId);

        _payBackLoan(_loanId, borrower, lender, loan);

        _resolveLoan(_loanId, borrower, loan, loanCoordinator);

        // Delete the loan from storage in order to achieve a substantial gas savings and to lessen the burden of
        // storage on Ethereum nodes, since we will never access this loan's details again, and the details are still
        // available through event data.
        delete loanIdToLoan[_loanId];
        delete loanIdToLoanExtras[_loanId];
    }

    /**
     * @notice This function is called by a lender once a loan has finished its duration and the borrower still has not
     * repaid. The lender can call this function to seize the underlying NFT collateral, although the lender gives up
     * all rights to the principal-plus-collateral by doing so.
     *
     * This function is purposefully not pausable in order to prevent an attack where the contract admin's pause
     * the contract and hold hostage the NFT's that are still within it.
     *
     * We intentionally allow anybody to call this function, although only the lender will end up receiving the seized
     * collateral. We are exploring the possbility of incentivizing users to call this function by using some of the
     * admin funds.
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     */
    function liquidateOverdueLoan(uint32 _loanId) external nonReentrant {
        LoanChecksAndCalculations.checkLoanIdValidity(_loanId, hub);
        // Sanity check that payBackLoan() and liquidateOverdueLoan() have never been called on this loanId.
        // Depending on how the rest of the code turns out, this check may be unnecessary.
        require(!loanRepaidOrLiquidated[_loanId], "Loan already repaid/liquidated");

        (
            address borrower,
            address lender,
            LoanTerms memory loan,
            IDirectLoanCoordinator loanCoordinator
        ) = _getPartiesAndData(_loanId);

        // Ensure that the loan is indeed overdue, since we can only liquidate overdue loans.
        uint256 loanMaturityDate = uint256(loan.loanStartTime) + uint256(loan.loanDuration);
        require(block.timestamp > loanMaturityDate, "Loan is not overdue yet");

        require(msg.sender == lender, "Only lender can liquidate");

        _resolveLoan(_loanId, lender, loan, loanCoordinator);

        // Emit an event with all relevant details from this transaction.
        emit LoanLiquidated(
            _loanId,
            borrower,
            lender,
            loan.loanPrincipalAmount,
            loan.nftCollateralId,
            loanMaturityDate,
            block.timestamp,
            loan.nftCollateralContract
        );

        // Delete the loan from storage in order to achieve a substantial gas savings and to lessen the burden of
        // storage on Ethereum nodes, since we will never access this loan's details again, and the details are still
        // available through event data.
        delete loanIdToLoan[_loanId];
        delete loanIdToLoanExtras[_loanId];
    }

    /**
     * @notice this function initiates a flashloan to pull an airdrop from a tartget contract
     *
     * @param _loanId -
     * @param _target - address of the airdropping contract
     * @param _data - function selector to be called on the airdropping contract
     * @param _nftAirdrop - address of the used claiming nft in the drop
     * @param _nftAirdropId - id of the used claiming nft in the drop
     * @param _is1155 -
     * @param _nftAirdropAmount - amount in case of 1155
     */

    function pullAirdrop(
        uint32 _loanId,
        address _target,
        bytes calldata _data,
        address _nftAirdrop,
        uint256 _nftAirdropId,
        bool _is1155,
        uint256 _nftAirdropAmount
    ) external nonReentrant {
        LoanChecksAndCalculations.checkLoanIdValidity(_loanId, hub);
        require(!loanRepaidOrLiquidated[_loanId], "Loan already repaid/liquidated");

        LoanTerms memory loan = loanIdToLoan[_loanId];

        LoanAirdropUtils.pullAirdrop(
            _loanId,
            loan,
            _target,
            _data,
            _nftAirdrop,
            _nftAirdropId,
            _is1155,
            _nftAirdropAmount,
            hub
        );
    }

    /**
     * @notice this function creates a proxy contract wrapping the collateral to be able to catch an expected airdrop
     *
     * @param _loanId -
     */

    function wrapCollateral(uint32 _loanId) external nonReentrant {
        LoanChecksAndCalculations.checkLoanIdValidity(_loanId, hub);
        require(!loanRepaidOrLiquidated[_loanId], "Loan already repaid/liquidated");

        LoanTerms storage loan = loanIdToLoan[_loanId];

        _escrowTokens[loan.nftCollateralContract][loan.nftCollateralId] -= 1;
        (address instance, uint256 receiverId) = LoanAirdropUtils.wrapCollateral(_loanId, loan, hub);
        _escrowTokens[instance][receiverId] += 1;
    }

    /**
     * @notice This function can be called by either a lender or a borrower to cancel all off-chain orders that they
     * have signed that contain this nonce. If the off-chain orders were created correctly, there should only be one
     * off-chain order that contains this nonce at all.
     *
     * The nonce referred to here is not the same as an Ethereum account's nonce. We are referring
     * instead to nonces that are used by both the lender and the borrower when they are first signing off-chain NFTfi
     * orders. These nonces can be any uint256 value that the user has not previously used to sign an off-chain order.
     * Each nonce can be used at most once per user within NFTfi, regardless of whether they are the lender or the
     * borrower in that situation. This serves two purposes. First, it prevents replay attacks where an attacker would
     * submit a user's off-chain order more than once. Second, it allows a user to cancel an off-chain order by calling
     * NFTfi.cancelLoanCommitmentBeforeLoanHasBegun(), which marks the nonce as used and prevents any future loan from
     * using the user's off-chain order that contains that nonce.
     *
     * @param  _nonce - User nonce
     */
    function cancelLoanCommitmentBeforeLoanHasBegun(uint256 _nonce) external {
        require(!_nonceHasBeenUsedForUser[msg.sender][_nonce], "Invalid nonce");
        _nonceHasBeenUsedForUser[msg.sender][_nonce] = true;
    }

    /* ******************* */
    /* READ-ONLY FUNCTIONS */
    /* ******************* */

    /**
     * @notice This function can be used to view the current quantity of the ERC20 currency used in the specified loan
     * required by the borrower to repay their loan, measured in the smallest unit of the ERC20 currency.
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     *
     * @return The amount of the specified ERC20 currency required to pay back this loan, measured in the smallest unit
     * of the specified ERC20 currency.
     */
    function getPayoffAmount(uint32 _loanId) external view virtual returns (uint256);

    /**
     * @notice This function can be used to view whether a particular nonce for a particular user has already been used,
     * either from a successful loan or a cancelled off-chain order.
     *
     * @param _user - The address of the user. This function works for both lenders and borrowers alike.
     * @param  _nonce - The nonce referred to here is not the same as an Ethereum account's nonce. We are referring
     * instead to nonces that are used by both the lender and the borrower when they are first signing off-chain
     * NFTfi orders. These nonces can be any uint256 value that the user has not previously used to sign an off-chain
     * order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the lender or
     * the borrower in that situation. This serves two purposes:
     * - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     * - Second, it allows a user to cancel an off-chain order by calling NFTfi.cancelLoanCommitmentBeforeLoanHasBegun()
     * , which marks the nonce as used and prevents any future loan from using the user's off-chain order that contains
     * that nonce.
     *
     * @return A bool representing whether or not this nonce has been used for this user.
     */
    function getWhetherNonceHasBeenUsedForUser(address _user, uint256 _nonce) external view override returns (bool) {
        return _nonceHasBeenUsedForUser[_user][_nonce];
    }

    /**
     * @notice This function can be called by anyone to get the permit associated with the erc20 contract.
     *
     * @param _erc20 - The address of the erc20 contract.
     *
     * @return Returns whether the erc20 is permitted
     */
    function getERC20Permit(address _erc20) public view override returns (bool) {
        return erc20Permits[_erc20];
    }

    /* ****************** */
    /* INTERNAL FUNCTIONS */
    /* ****************** */

    /**
     * @dev makes possible to change loan duration and max repayment amount, loan duration even can be extended if
     * loan was expired but not liquidated. IMPORTANT: Frontend will have to propt the caller to do an ERC20 approve for
     * the fee amount from themselves (borrower/obligation reciept holder) to the lender (promissory note holder)
     *
     * @param _loanId - The unique identifier for the loan to be renegotiated
     * @param _newLoanDuration - The new amount of time (measured in seconds) that can elapse before the lender can
     * liquidate the loan and seize the underlying collateral NFT.
     * @param _newMaximumRepaymentAmount - The new maximum amount of money that the borrower would be required to
     * retrieve their collateral, measured in the smallest units of the ERC20 currency used for the loan. The
     * borrower will always have to pay this amount to retrieve their collateral, regardless of whether they repay
     * early.
     * @param _renegotiationFee Agreed upon fee in loan denomination that borrower pays for the lender and
     * the admin for the renegotiation, has to be paid with an ERC20 transfer loanERC20Denomination token,
     * uses transfer from, frontend will have to propmt an erc20 approve for this from the borrower to the lender,
     * admin fee is calculated by the loan's loanAdminFeeInBasisPoints value
     * @param _lenderNonce - The nonce referred to here is not the same as an Ethereum account's nonce. We are
     * referring instead to nonces that are used by both the lender and the borrower when they are first signing
     * off-chain NFTfi orders. These nonces can be any uint256 value that the user has not previously used to sign an
     * off-chain order. Each nonce can be used at most once per user within NFTfi, regardless of whether they are the
     * lender or the borrower in that situation. This serves two purposes:
     * - First, it prevents replay attacks where an attacker would submit a user's off-chain order more than once.
     * - Second, it allows a user to cancel an off-chain order by calling NFTfi.cancelLoanCommitmentBeforeLoanHasBegun()
     , which marks the nonce as used and prevents any future loan from using the user's off-chain order that contains
     * that nonce.
     * @param _expiry - The date when the renegotiation offer expires
     * @param _lenderSignature - The ECDSA signature of the lender, obtained off-chain ahead of time, signing the
     * following combination of parameters:
     * - _loanId
     * - _newLoanDuration
     * - _newMaximumRepaymentAmount
     * - _lender
     * - _expiry
     * - address of this contract
     * - chainId
     */
    function _renegotiateLoan(
        uint32 _loanId,
        uint32 _newLoanDuration,
        uint256 _newMaximumRepaymentAmount,
        uint256 _renegotiationFee,
        uint256 _lenderNonce,
        uint256 _expiry,
        bytes memory _lenderSignature
    ) internal {
        LoanTerms storage loan = loanIdToLoan[_loanId];

        (address borrower, address lender) = LoanChecksAndCalculations.renegotiationChecks(
            loan,
            _loanId,
            _newLoanDuration,
            _newMaximumRepaymentAmount,
            _lenderNonce,
            hub
        );

        _nonceHasBeenUsedForUser[lender][_lenderNonce] = true;

        require(
            NFTfiSigningUtils.isValidLenderRenegotiationSignature(
                _loanId,
                _newLoanDuration,
                _newMaximumRepaymentAmount,
                _renegotiationFee,
                Signature({signer: lender, nonce: _lenderNonce, expiry: _expiry, signature: _lenderSignature})
            ),
            "Renegotiation signature is invalid"
        );

        uint256 renegotiationAdminFee;
        /**
         * @notice Transfers fee to the lender immediately
         * @dev implements Checks-Effects-Interactions pattern by modifying state only after
         * the transfer happened successfully, we also add the nonReentrant modifier to
         * the pbulic versions
         */
        if (_renegotiationFee > 0) {
            renegotiationAdminFee = LoanChecksAndCalculations.computeAdminFee(
                _renegotiationFee,
                loan.loanAdminFeeInBasisPoints
            );
            // Transfer principal-plus-interest-minus-fees from the caller (always has to be borrower) to lender
            IERC20(loan.loanERC20Denomination).safeTransferFrom(
                borrower,
                lender,
                _renegotiationFee - renegotiationAdminFee
            );
            // Transfer fees from the caller (always has to be borrower) to admins
            IERC20(loan.loanERC20Denomination).safeTransferFrom(borrower, owner(), renegotiationAdminFee);
        }

        loan.loanDuration = _newLoanDuration;
        loan.maximumRepaymentAmount = _newMaximumRepaymentAmount;

        emit LoanRenegotiated(
            _loanId,
            borrower,
            lender,
            _newLoanDuration,
            _newMaximumRepaymentAmount,
            _renegotiationFee,
            renegotiationAdminFee
        );
    }

    /**
     * @dev Transfer collateral NFT from borrower to this contract and principal from lender to the borrower and
     * registers the new loan through the loan coordinator.
     *
     * @param _loanType - The type of loan it is being created
     * @param _loanTerms - Struct containing the loan's settings
     * @param _loanExtras - Struct containing some loan's extra settings, needed to avoid stack too deep
     * @param _lender - The address of the lender.
     * @param _referrer - The address of the referrer who found the lender matching the listing, Zero address to signal
     * that there is no referrer.
     */
    function _createLoan(
        bytes32 _loanType,
        LoanTerms memory _loanTerms,
        LoanExtras memory _loanExtras,
        address _borrower,
        address _lender,
        address _referrer
    ) internal returns (uint32) {
        // Transfer collateral from borrower to this contract to be held until
        // loan completion.
        _transferNFT(_loanTerms, _borrower, address(this));

        return _createLoanNoNftTransfer(_loanType, _loanTerms, _loanExtras, _borrower, _lender, _referrer);
    }

    /**
     * @dev Transfer principal from lender to the borrower and
     * registers the new loan through the loan coordinator.
     *
     * @param _loanType - The type of loan it is being created
     * @param _loanTerms - Struct containing the loan's settings
     * @param _loanExtras - Struct containing some loan's extra settings, needed to avoid stack too deep
     * @param _lender - The address of the lender.
     * @param _referrer - The address of the referrer who found the lender matching the listing, Zero address to signal
     * that there is no referrer.
     */
    function _createLoanNoNftTransfer(
        bytes32 _loanType,
        LoanTerms memory _loanTerms,
        LoanExtras memory _loanExtras,
        address _borrower,
        address _lender,
        address _referrer
    ) internal returns (uint32 loanId) {
        _escrowTokens[_loanTerms.nftCollateralContract][_loanTerms.nftCollateralId] += 1;

        uint256 referralfee = LoanChecksAndCalculations.computeReferralFee(
            _loanTerms.loanPrincipalAmount,
            _loanExtras.referralFeeInBasisPoints,
            _referrer
        );
        uint256 principalAmount = _loanTerms.loanPrincipalAmount - referralfee;
        if (referralfee > 0) {
            // Transfer the referral fee from lender to referrer.
            IERC20(_loanTerms.loanERC20Denomination).safeTransferFrom(_lender, _referrer, referralfee);
        }
        // Transfer principal from lender to borrower.
        IERC20(_loanTerms.loanERC20Denomination).safeTransferFrom(_lender, _borrower, principalAmount);

        // Issue an ERC721 promissory note to the lender that gives them the
        // right to either the principal-plus-interest or the collateral,
        // and an obligation note to the borrower that gives them the
        // right to pay back the loan and get the collateral back.
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(hub.getContract(LOAN_COORDINATOR));
        loanId = loanCoordinator.registerLoan(_lender, _loanType);

        // Add the loan to storage before moving collateral/principal to follow
        // the Checks-Effects-Interactions pattern.
        loanIdToLoan[loanId] = _loanTerms;
        loanIdToLoanExtras[loanId] = _loanExtras;

        return loanId;
    }

    /**
     * @dev Transfers several types of NFTs using a wrapper that knows how to handle each case.
     *
     * @param _loanTerms - Struct containing all the loan's parameters
     * @param _sender - Current owner of the NFT
     * @param _recipient - Recipient of the transfer
     */
    function _transferNFT(
        LoanTerms memory _loanTerms,
        address _sender,
        address _recipient
    ) internal {
        Address.functionDelegateCall(
            _loanTerms.nftCollateralWrapper,
            abi.encodeWithSelector(
                INftWrapper(_loanTerms.nftCollateralWrapper).transferNFT.selector,
                _sender,
                _recipient,
                _loanTerms.nftCollateralContract,
                _loanTerms.nftCollateralId
            ),
            "NFT not successfully transferred"
        );
    }

    /**
     * @notice This function is called by a anyone to repay a loan. It can be called at any time after the loan has
     * begun and before loan expiry.. The caller will pay a pro-rata portion of their interest if the loan is paid off
     * early and the loan is pro-rated type, but the complete repayment amount if it is fixed type.
     * The the borrower (current owner of the obligation note) will get the collaterl NFT back.
     *
     * This function is purposefully not pausable in order to prevent an attack where the contract admin's pause the
     * contract and hold hostage the NFT's that are still within it.
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     */
    function _payBackLoan(
        uint32 _loanId,
        address _borrower,
        address _lender,
        LoanTerms memory _loan
    ) internal {
        // Fetch loan details from storage, but store them in memory for the sake of saving gas.
        LoanExtras memory loanExtras = loanIdToLoanExtras[_loanId];

        (uint256 adminFee, uint256 payoffAmount) = _payoffAndFee(_loan);

        // Transfer principal-plus-interest-minus-fees from the caller to lender
        IERC20(_loan.loanERC20Denomination).safeTransferFrom(msg.sender, _lender, payoffAmount);

        uint256 revenueShare = LoanChecksAndCalculations.computeRevenueShare(
            adminFee,
            loanExtras.revenueShareInBasisPoints
        );
        // PermittedPartners contract doesn't allow to set a revenueShareInBasisPoints for address zero so revenuShare
        // > 0 implies that revenueSharePartner ~= address(0), BUT revenueShare can be zero for a partener when the
        // adminFee is low
        if (revenueShare > 0 && loanExtras.revenueSharePartner != address(0)) {
            adminFee -= revenueShare;
            // Transfer revenue share from the caller to permitted partner
            IERC20(_loan.loanERC20Denomination).safeTransferFrom(
                msg.sender,
                loanExtras.revenueSharePartner,
                revenueShare
            );
        }
        // Transfer fees from the caller to admins
        IERC20(_loan.loanERC20Denomination).safeTransferFrom(msg.sender, owner(), adminFee);

        // Emit an event with all relevant details from this transaction.
        emit LoanRepaid(
            _loanId,
            _borrower,
            _lender,
            _loan.loanPrincipalAmount,
            _loan.nftCollateralId,
            payoffAmount,
            adminFee,
            revenueShare,
            loanExtras.revenueSharePartner, // this could be a non address zero even if revenueShare is 0
            _loan.nftCollateralContract,
            _loan.loanERC20Denomination
        );
    }

    /**
     * @notice A convenience function with shared functionality between `payBackLoan` and `liquidateOverdueLoan`.
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param _nftReceiver - The receiver of the collateral nft. The borrower when `payBackLoan` or the lender when
     * `liquidateOverdueLoan`.
     * @param _loanTerms - The main Loan Terms struct. This data is saved upon loan creation on loanIdToLoan.
     * @param _loanCoordinator - The loan coordinator used when creating the loan.
     */
    function _resolveLoan(
        uint32 _loanId,
        address _nftReceiver,
        LoanTerms memory _loanTerms,
        IDirectLoanCoordinator _loanCoordinator
    ) internal {
        _resolveLoanNoNftTransfer(_loanId, _loanTerms, _loanCoordinator);
        // Transfer collateral from this contract to the lender, since the lender is seizing collateral for an overdue
        // loan
        _transferNFT(_loanTerms, address(this), _nftReceiver);
    }

    /**
     * @notice Resolving the loan without trasferring the nft to provide a base for the bundle
     * break up of the bundled loans
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     * @param _loanTerms - The main Loan Terms struct. This data is saved upon loan creation on loanIdToLoan.
     * @param _loanCoordinator - The loan coordinator used when creating the loan.
     */
    function _resolveLoanNoNftTransfer(
        uint32 _loanId,
        LoanTerms memory _loanTerms,
        IDirectLoanCoordinator _loanCoordinator
    ) internal {
        // Mark loan as liquidated before doing any external transfers to follow the Checks-Effects-Interactions design
        // pattern
        loanRepaidOrLiquidated[_loanId] = true;

        _escrowTokens[_loanTerms.nftCollateralContract][_loanTerms.nftCollateralId] -= 1;

        // Destroy the lender's promissory note for this loan and borrower obligation receipt
        _loanCoordinator.resolveLoan(_loanId);
    }

    /**
     * @notice This function can be called by admins to change the permitted status of an ERC20 currency. This includes
     * both adding an ERC20 currency to the permitted list and removing it.
     *
     * @param _erc20 - The address of the ERC20 currency whose permit list status changed.
     * @param _permit - The new status of whether the currency is permitted or not.
     */
    function _setERC20Permit(address _erc20, bool _permit) internal {
        require(_erc20 != address(0), "erc20 is zero address");

        erc20Permits[_erc20] = _permit;

        emit ERC20Permit(_erc20, _permit);
    }

    /**
     * @dev Performs some validation checks over loan parameters
     *
     */
    function _loanSanityChecks(LoanData.Offer memory _offer, address _nftWrapper) internal view {
        require(getERC20Permit(_offer.loanERC20Denomination), "Currency denomination is not permitted");
        require(_nftWrapper != address(0), "NFT collateral contract is not permitted");
        require(uint256(_offer.loanDuration) <= maximumLoanDuration, "Loan duration exceeds maximum loan duration");
        require(uint256(_offer.loanDuration) != 0, "Loan duration cannot be zero");
        require(
            _offer.loanAdminFeeInBasisPoints == adminFeeInBasisPoints,
            "The admin fee has changed since this order was signed."
        );
    }

    /**
     * @dev reads some variable values of a loan for payback functions, created to reduce code repetition
     */
    function _getPartiesAndData(uint32 _loanId)
        internal
        view
        returns (
            address borrower,
            address lender,
            LoanTerms memory loan,
            IDirectLoanCoordinator loanCoordinator
        )
    {
        loanCoordinator = IDirectLoanCoordinator(hub.getContract(LOAN_COORDINATOR));
        IDirectLoanCoordinator.Loan memory loanCoordinatorData = loanCoordinator.getLoanData(_loanId);
        uint256 smartNftId = loanCoordinatorData.smartNftId;
        // Fetch loan details from storage, but store them in memory for the sake of saving gas.
        loan = loanIdToLoan[_loanId];
        if (loan.borrower != address(0)) {
            borrower = loan.borrower;
        } else {
            // Fetch current owner of loan obligation note.
            borrower = IERC721(loanCoordinator.obligationReceiptToken()).ownerOf(smartNftId);
        }
        lender = IERC721(loanCoordinator.promissoryNoteToken()).ownerOf(smartNftId);
    }

    /**
     * @dev Creates a `LoanExtras` struct using data sent as the borrower's extra settings.
     * This is needed in order to avoid stack too deep issues.
     */
    function _setupLoanExtras(address _revenueSharePartner, uint16 _referralFeeInBasisPoints)
        internal
        view
        returns (LoanExtras memory)
    {
        // Save loan details to a struct in memory first, to save on gas if any
        // of the below checks fail, and to avoid the "Stack Too Deep" error by
        // clumping the parameters together into one struct held in memory.
        return
            LoanExtras({
                revenueSharePartner: _revenueSharePartner,
                revenueShareInBasisPoints: LoanChecksAndCalculations.getRevenueSharePercent(_revenueSharePartner, hub),
                referralFeeInBasisPoints: _referralFeeInBasisPoints
            });
    }

    /**
     * @dev Calculates the payoff amount and admin fee
     */
    function _payoffAndFee(LoanTerms memory _loanTerms) internal view virtual returns (uint256, uint256);

    /**
     * @dev Checks that the collateral is a supported contracts and returns what wrapper to use for the loan's NFT
     * collateral contract.
     *
     * @param _nftCollateralContract - The address of the the NFT collateral contract.
     *
     * @return Address of the NftWrapper to use for the loan's NFT collateral.
     */
    function _getWrapper(address _nftCollateralContract) internal view returns (address) {
        return IPermittedNFTs(hub.getContract(ContractKeys.PERMITTED_NFTS)).getNFTWrapper(_nftCollateralContract);
    }
}

// contracts/external/lp-1/loans/direct/loanTypes/DirectLoanFixedOffer.sol

/**
 * @title  DirectLoanFixed
 * @author NFTfi
 * @notice Main contract for NFTfi Direct Loans Fixed Type. This contract manages the ability to create NFT-backed
 * peer-to-peer loans of type Fixed (agreed to be a fixed-repayment loan) where the borrower pays the
 * maximumRepaymentAmount regardless of whether they repay early or not.
 *
 * There are two ways to commence an NFT-backed loan:
 *
 * a. The borrower accepts a lender's offer by calling `acceptOffer`.
 *   1. the borrower calls nftContract.approveAll(NFTfi), approving the NFTfi contract to move their NFT's on their
 * be1alf.
 *   2. the lender calls erc20Contract.approve(NFTfi), allowing NFTfi to move the lender's ERC20 tokens on their
 * behalf.
 *   3. the lender signs an off-chain message, proposing its offer terms.
 *   4. the borrower calls `acceptOffer` to accept these terms and enter into the loan. The NFT is stored in
 * the contract, the borrower receives the loan principal in the specified ERC20 currency, the lender receives an
 * NFTfi promissory note (in ERC721 form) that represents the rights to either the principal-plus-interest, or the
 * underlying NFT collateral if the borrower does not pay back in time, and the borrower receives obligation receipt
 * (in ERC721 form) that gives them the right to pay back the loan and get the collateral back.
 *
 * b. The lender accepts a borrowe's binding terms by calling `acceptListing`.
 *   1. the borrower calls nftContract.approveAll(NFTfi), approving the NFTfi contract to move their NFT's on their
 * be1alf.
 *   2. the lender calls erc20Contract.approve(NFTfi), allowing NFTfi to move the lender's ERC20 tokens on their
 * behalf.
 *   3. the borrower signs an off-chain message, proposing its binding terms.
 *   4. the lender calls `acceptListing` with an offer matching the binding terms and enter into the loan. The NFT is
 * stored in the contract, the borrower receives the loan principal in the specified ERC20 currency, the lender
 * receives an NFTfi promissory note (in ERC721 form) that represents the rights to either the principal-plus-interest,
 * or the underlying NFT collateral if the borrower does not pay back in time, and the borrower receives obligation
 * receipt (in ERC721 form) that gives them the right to pay back the loan and get the collateral back.
 *
 * The lender can freely transfer and trade this ERC721 promissory note as they wish, with the knowledge that
 * transferring the ERC721 promissory note tranfsers the rights to principal-plus-interest and/or collateral, and that
 * they will no longer have a claim on the loan. The ERC721 promissory note itself represents that claim.
 *
 * The borrower can freely transfer and trade this ERC721 obligaiton receipt as they wish, with the knowledge that
 * transferring the ERC721 obligaiton receipt tranfsers the rights right to pay back the loan and get the collateral
 * back.
 *
 *
 * A loan may end in one of two ways:
 * - First, a borrower may call NFTfi.payBackLoan() and pay back the loan plus interest at any time, in which case they
 * receive their NFT back in the same transaction.
 * - Second, if the loan's duration has passed and the loan has not been paid back yet, a lender can call
 * NFTfi.liquidateOverdueLoan(), in which case they receive the underlying NFT collateral and forfeit the rights to the
 * principal-plus-interest, which the borrower now keeps.
 */
contract DirectLoanFixedOffer is DirectLoanBaseMinimal {
    /* ********** */
    /* DATA TYPES */
    /* ********** */

    bytes32 public constant LOAN_TYPE = bytes32("DIRECT_LOAN_FIXED_OFFER");

    /* *********** */
    /* CONSTRUCTOR */
    /* *********** */

    /**
     * @dev Sets `hub` and permitted erc20-s
     *
     * @param _admin - Initial admin of this contract.
     * @param  _nftfiHub - NFTfiHub address
     * @param  _permittedErc20s - list of permitted ERC20 token contract addresses
     */
    constructor(
        address _admin,
        address _nftfiHub,
        address[] memory _permittedErc20s
    )
        DirectLoanBaseMinimal(
            _admin,
            _nftfiHub,
            ContractKeys.getIdFromStringKey("DIRECT_LOAN_COORDINATOR"),
            _permittedErc20s
        )
    {
        // solhint-disable-previous-line no-empty-blocks
    }

    /* ********* */
    /* FUNCTIONS */
    /* ********* */

    /**
     * @notice This function is called by the borrower when accepting a lender's offer to begin a loan.
     *
     * @param _offer - The offer made by the lender.
     * @param _signature - The components of the lender's signature.
     * @param _borrowerSettings - Some extra parameters that the borrower needs to set when accepting an offer.
     */
    function acceptOffer(
        Offer memory _offer,
        Signature memory _signature,
        BorrowerSettings memory _borrowerSettings
    ) external whenNotPaused nonReentrant {
        address nftWrapper = _getWrapper(_offer.nftCollateralContract);
        _loanSanityChecks(_offer, nftWrapper);
        _loanSanityChecksOffer(_offer);
        _acceptOffer(
            LOAN_TYPE,
            _setupLoanTerms(_offer, nftWrapper),
            _setupLoanExtras(_borrowerSettings.revenueSharePartner, _borrowerSettings.referralFeeInBasisPoints),
            _offer,
            _signature
        );
    }

    /* ******************* */
    /* READ-ONLY FUNCTIONS */
    /* ******************* */

    /**
     * @notice This function can be used to view the current quantity of the ERC20 currency used in the specified loan
     * required by the borrower to repay their loan, measured in the smallest unit of the ERC20 currency.
     *
     * @param _loanId  A unique identifier for this particular loan, sourced from the Loan Coordinator.
     *
     * @return The amount of the specified ERC20 currency required to pay back this loan, measured in the smallest unit
     * of the specified ERC20 currency.
     */
    function getPayoffAmount(uint32 _loanId) external view override returns (uint256) {
        LoanTerms storage loan = loanIdToLoan[_loanId];
        return loan.maximumRepaymentAmount;
    }

    /* ****************** */
    /* INTERNAL FUNCTIONS */
    /* ****************** */

    /**
     * @notice This function is called by the borrower when accepting a lender's offer to begin a loan.
     *
     * @param _loanType - The loan type being created.
     * @param _loanTerms - The main Loan Terms struct. This data is saved upon loan creation on loanIdToLoan.
     * @param _loanExtras - The main Loan Terms struct. This data is saved upon loan creation on loanIdToLoanExtras.
     * @param _offer - The offer made by the lender.
     * @param _signature - The components of the lender's signature.
     */
    function _acceptOffer(
        bytes32 _loanType,
        LoanTerms memory _loanTerms,
        LoanExtras memory _loanExtras,
        Offer memory _offer,
        Signature memory _signature
    ) internal {
        // Check loan nonces. These are different from Ethereum account nonces.
        // Here, these are uint256 numbers that should uniquely identify
        // each signature for each user (i.e. each user should only create one
        // off-chain signature for each nonce, with a nonce being any arbitrary
        // uint256 value that they have not used yet for an off-chain NFTfi
        // signature).
        require(!_nonceHasBeenUsedForUser[_signature.signer][_signature.nonce], "Lender nonce invalid");

        _nonceHasBeenUsedForUser[_signature.signer][_signature.nonce] = true;

        require(NFTfiSigningUtils.isValidLenderSignature(_offer, _signature), "Lender signature is invalid");

        address bundle = hub.getContract(ContractKeys.NFTFI_BUNDLER);
        require(_loanTerms.nftCollateralContract != bundle, "Collateral cannot be bundle");

        uint32 loanId = _createLoan(_loanType, _loanTerms, _loanExtras, msg.sender, _signature.signer, _offer.referrer);

        // Emit an event with all relevant details from this transaction.
        emit LoanStarted(loanId, msg.sender, _signature.signer, _loanTerms, _loanExtras);
    }

    /**
     * @dev Creates a `LoanTerms` struct using data sent as the lender's `_offer` on `acceptOffer`.
     * This is needed in order to avoid stack too deep issues.
     * Since this is a Fixed loan type loanInterestRateForDurationInBasisPoints is ignored.
     */
    function _setupLoanTerms(Offer memory _offer, address _nftWrapper) internal view returns (LoanTerms memory) {
        return
            LoanTerms({
                loanERC20Denomination: _offer.loanERC20Denomination,
                loanPrincipalAmount: _offer.loanPrincipalAmount,
                maximumRepaymentAmount: _offer.maximumRepaymentAmount,
                nftCollateralContract: _offer.nftCollateralContract,
                nftCollateralWrapper: _nftWrapper,
                nftCollateralId: _offer.nftCollateralId,
                loanStartTime: uint64(block.timestamp),
                loanDuration: _offer.loanDuration,
                loanInterestRateForDurationInBasisPoints: uint16(0),
                loanAdminFeeInBasisPoints: _offer.loanAdminFeeInBasisPoints,
                borrower: msg.sender
            });
    }

    /**
     * @dev Calculates the payoff amount and admin fee
     *
     * @param _loanTerms - Struct containing all the loan's parameters
     */
    function _payoffAndFee(LoanTerms memory _loanTerms)
        internal
        pure
        override
        returns (uint256 adminFee, uint256 payoffAmount)
    {
        // Calculate amounts to send to lender and admins
        uint256 interestDue = _loanTerms.maximumRepaymentAmount - _loanTerms.loanPrincipalAmount;
        adminFee = LoanChecksAndCalculations.computeAdminFee(
            interestDue,
            uint256(_loanTerms.loanAdminFeeInBasisPoints)
        );
        payoffAmount = _loanTerms.maximumRepaymentAmount - adminFee;
    }

    /**
     * @dev Function that performs some validation checks over loan parameters when accepting an offer
     *
     */
    function _loanSanityChecksOffer(LoanData.Offer memory _offer) internal pure {
        require(
            _offer.maximumRepaymentAmount >= _offer.loanPrincipalAmount,
            "Negative interest rate loans are not allowed."
        );
    }
}

// contracts/lp-migrations/LP1MigrationBase.sol

/**
 * @title LP1MigrationBase
 * @author Non-Fungible Technologies, Inc.
 *
 * This contract holds the common logic for the LP1Migration and LP1MigrationWIthItems contracts.
 */
abstract contract LP1MigrationBase is IMigrationBase, ReentrancyGuard, ERC721Holder, Ownable {
    using SafeERC20 for IERC20;

    event Migration(
        address indexed lender,
        address indexed borrower,
        uint256 oldLoanId,
        uint256 newLoanId
    );

    struct OperationContracts {
        IFeeController feeControllerV3;
        IOriginationController originationControllerV3;
        ILoanCore loanCoreV3;
        IERC721 borrowerNoteV3;
    }

    struct LP1Deployment {
        address directLoanFixedOffer;
        address loanCoordinator;
    }

    enum LoanType {
        V2,
        V2_1,
        V2_3,
        COLLECTION_V2,
        COLLECTION_V2_3
    }

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct OperationData {
        uint256 loanId;
        address borrower;
        LoanLibrary.LoanTerms newLoanTerms;
        address lender;
        uint160 nonce;
        uint8 v;
        bytes32 r;
        bytes32 s;
        LoanType loanType;
    }

    // Balancer vault contract
    /* solhint-disable var-name-mixedcase */
    IVault public immutable VAULT; // 0xBA12222222228d8Ba445958a75a0704d566BF2C8

    /// @notice V3 lending protocol contract references
    LP1Deployment[5] public deployments;

    IFeeController public immutable feeController;
    IOriginationController public immutable originationController;
    ILoanCore public immutable loanCore;
    IERC721 public immutable borrowerNote;

    /// @notice State variable used for checking the inheriting contract initiated the flash
    ///         loan. When a rollover function is called the borrowers address is cached here
    ///         and checked against the opData in the flash loan callback.
    address public borrower;

    /// @notice state variable for pausing the contract
    bool public paused;

    constructor(IVault _vault, OperationContracts memory _opContracts, LP1Deployment[] memory _deployments) {
        // input sanitization
        if (address(_vault) == address(0)) revert R_ZeroAddress("vault");
        if (address(_opContracts.feeControllerV3) == address(0)) revert R_ZeroAddress("feeControllerV3");
        if (address(_opContracts.originationControllerV3) == address(0)) revert R_ZeroAddress("originationControllerV3");
        if (address(_opContracts.loanCoreV3) == address(0)) revert R_ZeroAddress("loanCoreV3");
        if (address(_opContracts.borrowerNoteV3) == address(0)) revert R_ZeroAddress("borrowerNoteV3");

        // Set Balancer vault address
        VAULT = _vault;

        // Set lending protocol contract references
        feeController = IFeeController(_opContracts.feeControllerV3);
        originationController = IOriginationController(_opContracts.originationControllerV3);
        loanCore = ILoanCore(_opContracts.loanCoreV3);
        borrowerNote = IERC721(_opContracts.borrowerNoteV3);

        // Set LP1 deployment references
        require(_deployments.length == 5, "Invalid versions");

        deployments[0] = _deployments[0];
        deployments[1] = _deployments[1];
        deployments[2] = _deployments[2];
        deployments[3] = _deployments[3];
        deployments[4] = _deployments[4];
    }

    /**
     * @notice This helper function to calculate the net amounts required to repay the flash loan.
     *         This function will return the total amount due back to the lending pool. The amount
     *         that needs to be paid by the borrower, in the case that the new loan does not cover
     *         the flashAmountDue. Lastly, the amount that will be sent back to the borrower, in
     *         the case that the new loan covers more than the flashAmountDue.
     *
     * @param amount                  The amount that was borrowed in Flash Loan.
     * @param premium                 The fees that are due back to the lending pool.
     * @param originationFee          The origination fee for the new loan.
     * @param newPrincipal            The principal of the new loan.
     *
     * @return flashAmountDue         The total amount due back to the lending pool.
     * @return needFromBorrower       The amount borrower owes if new loan cannot repay flash loan.
     * @return leftoverPrincipal      The amount to send to borrower if new loan amount is more than
     *                                amount required to repay flash loan.
     */
    function _ensureFunds(
        uint256 amount,
        uint256 premium,
        uint256 originationFee,
        uint256 newPrincipal
    ) internal pure returns (uint256 flashAmountDue, uint256 needFromBorrower, uint256 leftoverPrincipal) {
        // total amount due to flash loan contract
        flashAmountDue = amount + premium;
        // amount that will be received when starting the new loan
        uint256 willReceive = newPrincipal - ((newPrincipal * originationFee) / 1e4);

        if (flashAmountDue > willReceive) {
            // Not enough - have borrower pay the difference
            needFromBorrower = flashAmountDue - willReceive;
        } else if (willReceive > flashAmountDue) {
            // Too much - will send extra to borrower
            leftoverPrincipal = willReceive - flashAmountDue;
        }

        // Either leftoverPrincipal or needFromBorrower should be 0
        if (leftoverPrincipal != 0 && needFromBorrower != 0) {
            revert MR_FundsConflict(leftoverPrincipal, needFromBorrower);
        }
    }

    /**
     * @notice Helper function to repay the loan. Takes the obligationReceiptToken from the borrower, and
     *         approves the directLoanFixedOffer contract to spend the payable currency received from flash loan.
     *         Repays the loan, and ensures this contract holds the collateral after the loan is repaid.
     *
     * @param loanTerms                The loan terms for the loan to be repaid.
     * @param borrower_                The address of the borrower for the loan to be repaid (trailing underscore
                                        to differentiate from the borrower state variable)
     * @param loanId                   The id of the loan to be repaid.
     */
    function _repayLoan(
        LoanData.LoanTerms memory loanTerms,
        address borrower_,
        uint32 loanId,
        LoanType loanType
    ) internal {
        LP1Deployment memory addresses = deployments[uint256(loanType)];
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(addresses.loanCoordinator);
        DirectLoanFixedOffer directLoanFixedOffer = DirectLoanFixedOffer(addresses.directLoanFixedOffer);

        // Take obligationReceiptToken from borrower
        // Must be approved for withdrawal
        IDirectLoanCoordinator.Loan memory loanData = loanCoordinator.getLoanData(loanId);
        uint64 smartNftId = loanData.smartNftId;

        IERC721(loanCoordinator.obligationReceiptToken()).safeTransferFrom(
            borrower_,
            address(this),
            smartNftId
        );

        // Approve repayment
        IERC20(loanTerms.loanERC20Denomination).approve(
            address(directLoanFixedOffer),
            loanTerms.maximumRepaymentAmount
        );

        // Repay loan
        directLoanFixedOffer.payBackLoan(loanId);

        address collateralOwner = IERC721(loanTerms.nftCollateralContract).ownerOf(loanTerms.nftCollateralId);
        if (collateralOwner != address(this)) revert MR_NotCollateralOwner(collateralOwner);
    }

    /**
     * @notice Validates that the migration is valid. The borrower from the loan must be the caller.
     *         The new loan must have the same currency as the old loan. The new loan must use the same
     *         collateral as the old loan. If any of these conditionals are not met, the transaction
     *         will revert.
     *
     * @param sourceLoanTerms           The terms of the old loan.
     * @param newLoanTerms              The terms of the V3 loan.
     * @param loanId                    The ID of the old loan.
     */
    function _validateMigration(
        LoanData.LoanTerms memory sourceLoanTerms,
        LoanLibrary.LoanTerms calldata newLoanTerms,
        uint256 loanId,
        LoanType loanType
    ) internal view returns (address _borrower) {
        LP1Deployment memory addresses = deployments[uint256(loanType)];
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(addresses.loanCoordinator);

        IDirectLoanCoordinator.Loan memory loanCoordinatorData = loanCoordinator.getLoanData(
            uint32(loanId)
        );

        uint256 smartNftId = loanCoordinatorData.smartNftId;
        _borrower = IERC721(loanCoordinator.obligationReceiptToken()).ownerOf(
            smartNftId
        );

        if (_borrower != msg.sender) revert MR_CallerNotBorrower(msg.sender, _borrower);

        if (sourceLoanTerms.loanERC20Denomination != newLoanTerms.payableCurrency) {
            revert MR_CurrencyMismatch(sourceLoanTerms.loanERC20Denomination, newLoanTerms.payableCurrency);
        }

        if (sourceLoanTerms.nftCollateralContract != newLoanTerms.collateralAddress) {
            revert MR_CollateralMismatch(sourceLoanTerms.nftCollateralContract, newLoanTerms.collateralAddress);
        }

        if (sourceLoanTerms.nftCollateralId != newLoanTerms.collateralId) {
            revert MR_CollateralIdMismatch(sourceLoanTerms.nftCollateralId, newLoanTerms.collateralId);
        }
    }

    /**
     * @notice Helper function to get the loan terms for the loan.
     *
     * @param loanId                   The id of the loan for which the terms are needed.
     *
     * @return loanTerms               The terms associated with the loan id.
     */
    function _getLoanTerms(uint256 loanId, LoanType loanType) internal view returns (LoanData.LoanTerms memory) {
        (
            uint256 loanPrincipalAmount,
            uint256 maximumRepaymentAmount,
            uint256 nftCollateralId,
            address loanERC20Denomination,
            uint32 loanDuration,
            uint16 loanInterestRateForDurationInBasisPoints,
            uint16 loanAdminFeeInBasisPoints,
            address nftCollateralWrapper,
            uint64 loanStartTime,
            address nftCollateralContract,
            address _borrower
        ) = DirectLoanFixedOffer(deployments[uint256(loanType)].directLoanFixedOffer).loanIdToLoan(uint32(loanId));

        return LoanData.LoanTerms(
            loanPrincipalAmount,
            maximumRepaymentAmount,
            nftCollateralId,
            loanERC20Denomination,
            loanDuration,
            loanInterestRateForDurationInBasisPoints,
            loanAdminFeeInBasisPoints,
            nftCollateralWrapper,
            loanStartTime,
            nftCollateralContract,
            _borrower
        );
    }

    /**
     * @notice Function to be used by the contract owner to withdraw any ERC20 tokens that
     *         are sent to the contract and get stuck.
     */
    function flushToken(IERC20 token, address to) external override {
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "no balance");

        token.safeTransfer(to, balance);
    }

    /**
     * @notice Function to be used by the contract owner to pause the contract.
     *
     * @dev This function is only to be used if a vulnerability is found or the contract
     *      is no longer being used.
     *
     * @param _pause              The state to set the contract to.
     */
    function pause(bool _pause) external override onlyOwner {
        if (paused == _pause) revert R_StateAlreadySet();

        paused = _pause;

        emit PausedStateChanged(_pause);
    }

    /**
     * @notice This function ensures that at the start of every flash loan sequence, the borrower
     *         state is reset to address(0). The rollover functions that inherit this modifier set
     *         the borrower state while executing the rollover operations. At the end of the rollover
     *         the borrower state is reset to address(0).
     */
    modifier whenBorrowerReset() {
        if (borrower != address(0)) revert R_BorrowerNotReset(borrower);

        _;

        borrower = address(0);
    }
}

// contracts/lp-migrations/LP1Migration.sol

/**
 * @title LP1Migration
 * @author Non-Fungible Technologies, Inc.
 *
 * This contract is used to migrate a loan from other lending protocols to the Arcade
 * V3 lending protocol. The migration mechanism takes out a flash loan for the maximumRepaymentAmount
 * of the old loan from Balancer pool, repays the old loan, and starts a new loan on V3.
 * This contract can only used with token-based signatures.
 * To perform a migration with items, use the LP1MigrationWithItems contract.
 *
 * This contract only works with ERC721 collateral.
 */
contract LP1Migration is ILP1Migration, LP1MigrationBase {
    using SafeERC20 for IERC20;

    constructor(IVault _vault, OperationContracts memory _opContracts, LP1Deployment[] memory _deployments)
        LP1MigrationBase(_vault, _opContracts, _deployments) {}

    /**
     * @notice Migrate a loan from LP1 to V3. Validates new loan terms against the
     *         old terms. Takes out Flash Loan for maximumRepaymentAmount, repays old
     *         loan, and starts new loan on V3.
     *
     * @param loanId                 The ID of the LP1 loan to be migrated.
     * @param newLoanTerms           The terms of the new loan.
     * @param lender                 The address of the lender.
     * @param nonce                  The nonce for the signature.
     * @param sig                    The signature for new loan.
     */
    function migrateLoan(
        uint256 loanId, // LP1 loanId
        LoanLibrary.LoanTerms calldata newLoanTerms,
        address lender,
        uint160 nonce,
        Signature calldata sig,
        LoanType loanType
    ) external whenBorrowerReset {
        if (paused) revert MR_Paused();

        LoanData.LoanTerms memory loanTerms = _getLoanTerms(loanId, loanType);
        (address _borrower) = _validateMigration(loanTerms, newLoanTerms, loanId, loanType);

        // cache borrower address for flash loan callback
        borrower = _borrower;
        if (borrower == address(0)) revert R_ZeroAddress("borrower");

        IERC20[] memory assets = new IERC20[](1);
        assets[0] = IERC20(loanTerms.loanERC20Denomination);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = loanTerms.maximumRepaymentAmount;

        bytes memory params = abi.encode(
            OperationData({
                loanId: loanId,
                borrower: borrower,
                newLoanTerms: newLoanTerms,
                lender: lender,
                nonce: nonce,
                v: sig.v,
                r: sig.r,
                s: sig.s,
                loanType: loanType
            })
        );

        // Flash loan based on principal + interest
        VAULT.flashLoan(this, assets, amounts, params);
    }

    /**
     * @notice Callback function for flash loan.
     *
     * @dev The caller of this function must be the lending pool.
     *
     * @param assets                 The ERC20 address that was borrowed in Flash Loan.
     * @param amounts                The amount that was borrowed in Flash Loan.
     * @param feeAmounts             The fees that are due to the lending pool.
     * @param params                 The data to be executed after receiving Flash Loan.
     */
    function receiveFlashLoan(
        IERC20[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata params
    ) external nonReentrant {
        if (msg.sender != address(VAULT)) revert MR_UnknownCaller(msg.sender, address(VAULT));

        OperationData memory opData = abi.decode(params, (OperationData));

        // verify this contract started the flash loan
        if (opData.borrower != borrower) revert R_UnknownBorrower(opData.borrower, borrower);
        // borrower must be set
        if (borrower == address(0)) revert R_ZeroAddress("borrower");

        _executeOperation(assets, amounts, feeAmounts, opData);
    }

    /**
     * @notice Executes repayment of old loan and initialization of new loan with lender
     *         specified item predicates. Any funds that are not covered by closing out
     *         the old loan must be covered by the borrower.
     *
     * @param assets                 The ERC20 that was borrowed in Flash Loan.
     * @param amounts                The amount that was borrowed in Flash Loan.
     * @param premiums               The fees that are due back to the lending pool.
     * @param opData                 The data to be executed after receiving Flash Loan.
     */
    function _executeOperation(
        IERC20[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        OperationData memory opData
    ) internal {
        LP1Deployment memory addresses = deployments[uint256(opData.loanType)];
        IDirectLoanCoordinator loanCoordinator = IDirectLoanCoordinator(addresses.loanCoordinator);

        // Get smartNFTId to look up lender promissoryNote and borrower obligationReceipt
        IDirectLoanCoordinator.Loan memory loanData = loanCoordinator.getLoanData(uint32(opData.loanId));

        address borrower = IERC721(loanCoordinator.obligationReceiptToken()).ownerOf(loanData.smartNftId);
        address lender = IERC721(loanCoordinator.promissoryNoteToken()).ownerOf(loanData.smartNftId);

        // Do accounting to figure out amount each party needs to receive
        (uint256 flashAmountDue, uint256 needFromBorrower, uint256 leftoverPrincipal) = _ensureFunds(
            amounts[0],
            premiums[0],
            uint256(
                IFeeController(feeController).getLendingFee(
                    // FL_01 - borrower origination fee
                    keccak256("BORROWER_ORIGINATION_FEE")
                )
            ),
            opData.newLoanTerms.principal
        );

        IERC20 asset = IERC20(assets[0]);

        if (needFromBorrower > 0) {
            if (asset.balanceOf(borrower) < needFromBorrower) {
                revert MR_InsufficientFunds(borrower, needFromBorrower, asset.balanceOf(opData.borrower));
            }
            if (asset.allowance(borrower, address(this)) < needFromBorrower) {
                revert MR_InsufficientAllowance(
                    borrower,
                    needFromBorrower,
                    asset.allowance(borrower, address(this))
                );
            }
        }

        {
            LoanData.LoanTerms memory loanTerms = _getLoanTerms(uint32(opData.loanId), opData.loanType);

            _repayLoan(loanTerms, borrower, uint32(opData.loanId), opData.loanType);

            uint256 newLoanId = _initializeNewLoan(borrower, opData.lender, opData);

            emit Migration(
                lender,
                borrower,
                uint32(opData.loanId), // old loanId
                newLoanId
            );
        }

        if (leftoverPrincipal > 0) {
            asset.safeTransfer(borrower, leftoverPrincipal);
        } else if (needFromBorrower > 0) {
            asset.safeTransferFrom(borrower, address(this), needFromBorrower);
        }

        // Make flash loan repayment
        // Balancer requires a transfer back to the vault
        asset.safeTransfer(address(VAULT), flashAmountDue);
    }

    /**
     * @notice Helper function to initialize the new loan using a collection wide offer. Approves
     *         the V3 Loan Core contract to take the collateral, then starts the new loan. Once
     *         the new loan is started, the borrowerNote is sent to the borrower.
     *
     * @param borrower                 The address of the borrower.
     * @param lender                   The address of the new lender.
     * @param opData                   The data used to initialize new V3 loan with items.
     *
     * @return newLoanId               V3 loanId for the new loan that is started.
     */
    function _initializeNewLoan(
        address borrower,
        address lender,
        OperationData memory opData
    ) internal returns (uint256) {
        // approve originationController
        IERC721(opData.newLoanTerms.collateralAddress).approve(address(loanCore), opData.newLoanTerms.collateralId);

        // start new loan
        // stand in for borrower to meet OriginationController's requirements
        uint256 newLoanId = IOriginationController(originationController).initializeLoan(
            opData.newLoanTerms,
            address(this),
            lender,
            IOriginationController.Signature({ v: opData.v, r: opData.r, s: opData.s, extraData: "0x" }),
            opData.nonce
        );

        IERC721(address(borrowerNote)).safeTransferFrom(address(this), borrower, newLoanId);

        return newLoanId;
    }

    receive() external payable {}
}
