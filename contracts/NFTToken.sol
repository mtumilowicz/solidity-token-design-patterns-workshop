// contracts/NFTToken.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Ownable } from "@openzeppelin/contracts@5.0.0/access/Ownable.sol";

contract NFTToken is Ownable {
    event Mint(address indexed _to, uint256 indexed _tokenId, bytes32 _ipfsHash);
    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);
    event Withdrawal(address indexed recipient, uint256 amount);

    uint256 tokenCounter = 1;
    mapping(uint256 => address) internal idToOwner;

    constructor() Ownable(msg.sender) {
        // Additional constructor logic for XYZ
    }

    function mint(address _to, bytes32 _ipfsHash) payable public {
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

    fallback() external payable { revert(); }
}