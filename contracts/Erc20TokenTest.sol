// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "remix_tests.sol";
import "../contracts/Erc20Token.sol";

contract Erc20TokenTest {

    Erc20Token myToken;
    address owner;
    address recipient;

    function beforeEach() public {
        myToken = new Erc20Token(1000);
        owner = address(this);
        recipient = address(0x123);
    }

    function testTransfer() public {
        Assert.equal(myToken.balanceOf(owner), 1000, "Incorrect initial balance for owner");
        Assert.equal(myToken.balanceOf(recipient), 0, "Incorrect initial balance for recipient");

        myToken.transfer(recipient, 500);

        Assert.equal(myToken.balanceOf(owner), 500, "Incorrect balance for owner after transfer");
        Assert.equal(myToken.balanceOf(recipient), 500, "Incorrect balance for recipient after transfer");
    }

}
