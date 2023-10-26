// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "remix_tests.sol";
import "remix_accounts.sol";
import "../contracts/Erc1155Token.sol";

contract Erc1155TokenTest {
    Erc1155Token public token;
    address public owner;

    constructor() payable {
        token = new Erc1155Token();
        owner = address(this);
    }

    /// #sender: account-1
    function testTransferThorHammer() public payable {
        // given
        uint256 belongsToOwner = token.balanceOf(owner, token.THOR_HAMMER());
        Assert.equal(belongsToOwner, 1, "initially throw hammer belongs to owner");

        // and
        address recipient = TestsAccounts.getAccount(2);

        // when
        token.safeTransferFrom(owner, recipient, token.THOR_HAMMER(), 1, new bytes(0));

        // then
        uint256 belongsToRecipient = token.balanceOf(recipient, token.THOR_HAMMER());
        Assert.equal(belongsToRecipient, 1, "Thor Hammer should belong to recipient");
    }
}
