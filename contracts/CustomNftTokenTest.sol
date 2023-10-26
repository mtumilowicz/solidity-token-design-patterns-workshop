// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "remix_tests.sol";
import "remix_accounts.sol";
import "../contracts/CustomNftToken.sol";

contract CustomNftTokenTest {

    CustomNftToken token;

    function beforeEach() public {
        token = new CustomNftToken();
    }

    /// #sender: account-1
    /// #value: 10
    function checkMint() public payable {
        // given
        address newOwner = msg.sender;

        // when
        token.mint{value: 10 wei}(newOwner, "ipfs_hash");

        // then
        Assert.equal(token.idToOwner(1), newOwner, "new owner should be msg.sender");
        Assert.equal(token.getContractBalance(), 10 wei, "contract balance should be 10 wei after minting");
    }

    /// #sender: account-1
    /// #value: 10
    function checkTransfer() public payable {
        // given
        token.mint{value: 10 wei}(msg.sender, "ipfs_hash");

        // and
        address recipient = TestsAccounts.getAccount(2);
        uint tokenId = 1;

        // when
        token.transfer(recipient, tokenId);

        // then
        Assert.equal(token.idToOwner(tokenId), recipient, "dupa");
    }
}
