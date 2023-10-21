// contracts/GameItem.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721URIStorage, ERC721} from "@openzeppelin/contracts@5.0.0/token/ERC721/extensions/ERC721URIStorage.sol";
import {ERC721Enumerable} from "@openzeppelin/contracts@5.0.0/token/ERC721/extensions/ERC721Enumerable.sol";
import {AccessControl} from "@openzeppelin/contracts@5.0.0/access/AccessControl.sol";

contract GameItem is ERC721URIStorage, ERC721Enumerable, AccessControl {

    bytes32 public immutable ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public immutable MINER_ROLE = keccak256("MINER_ROLE");
    string private _baseTokenURI;

    // https://gateway.pinata.cloud/ipfs/QmXLdCoTPVZ8Vf5PrEZR1awPKR8PvxmyEakaR5ummPCPnh/{id}.json>
    // MichiNFT, MIC, ipfs://QmZbWNKJPAjxXuNFSEaksCJVd1M6DaKQViJBYPK2BdpDEP/
    constructor(string memory name, string memory symbol, string memory baseTokenURI) ERC721(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(ADMIN_ROLE, _msgSender());
        _grantRole(MINER_ROLE, _msgSender());
        _baseTokenURI = baseTokenURI;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Enumerable, AccessControl, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _increaseBalance(address account, uint128 value) internal virtual override(ERC721, ERC721Enumerable) {
        super._increaseBalance(account, value);
    }

    function _update(address to, uint256 tokenId, address auth) internal virtual override(ERC721, ERC721Enumerable) returns (address) {
        return super._update(to, tokenId, auth);
    }

    function tokenURI(uint256 tokenId) public view virtual override(ERC721, ERC721URIStorage) returns (string memory) {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    function safeMine(address to) external onlyRole(MINER_ROLE) {
        uint256 tokenId = totalSupply() + 1;
        _safeMint(to, tokenId);
    }

    function burn(uint256 tokenId) external onlyRole(ADMIN_ROLE) {
        _burn(tokenId);
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    function setBaseURI(string memory newBaseURI) external onlyRole(ADMIN_ROLE) {
        _baseTokenURI = newBaseURI;
    }

}
