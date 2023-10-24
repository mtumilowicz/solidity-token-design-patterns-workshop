// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Ownable } from "@openzeppelin/contracts@5.0.0/access/Ownable.sol";

contract CustomNftTokenOwnable is Ownable {
    event Mint(address indexed _to, uint256 indexed _tokenId, string _ipfsHash);
    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);
    event Withdrawal(address indexed recipient, uint256 amount);

    uint256 tokenCounter = 1;
    mapping(uint256 => address) internal idToOwner;

    constructor() Ownable(msg.sender) { }

    function mint(address _to, string calldata _ipfsHash) payable public {
        require(msg.value == 1 ether, "Cost of the token is 1 ETH");

        uint256 _tokenId = tokenCounter;
        idToOwner[_tokenId] = _to;
        tokenCounter++;
        emit Mint(_to, _tokenId, _ipfsHash);
    }

    function transfer(address _to, uint256 _tokenId) public {
        require(msg.sender == idToOwner[_tokenId]);
        idToOwner[_tokenId] = _to;
        emit Transfer(msg.sender, _to, _tokenId);
    }

    function withdraw() public onlyOwner {
        uint256 contractBalance = address(this).balance;
        require(contractBalance > 0, "No ETH to withdraw");

        payable(owner()).transfer(contractBalance);
        emit Withdrawal(owner(), contractBalance);
    }

    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    modifier hasBalance() {
        uint256 contractBalance = address(this).balance;
        require(contractBalance > 0, "No ETH to withdraw");
        _;
    }

    receive() external payable { revert(); }

    fallback() external payable { revert(); }
}