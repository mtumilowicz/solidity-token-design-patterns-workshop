// contracts/GameItem.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721URIStorage, ERC721} from "@openzeppelin/contracts@5.0.0/token/ERC721/extensions/ERC721URIStorage.sol";
import {ERC721Enumerable} from "@openzeppelin/contracts@5.0.0/token/ERC721/extensions/ERC721Enumerable.sol";
import {AccessControl} from "@openzeppelin/contracts@5.0.0/access/AccessControl.sol";

contract GameItem is ERC721URIStorage, ERC721Enumerable, AccessControl {

    bytes32 public immutable ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public immutable MINER_ROLE = keccak256("MINER_ROLE");

    constructor() ERC721("GameItem", "ITM") {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(ADMIN_ROLE, _msgSender());
        _grantRole(MINER_ROLE, _msgSender());
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, _msgSender()), "Must have admin role");
        _;
    }

    modifier onlyMiner() {
        require(hasRole(MINER_ROLE, _msgSender()), "Must have miner role");
        _;
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

    function safeMine(address to, string memory uri) external onlyMiner {
        uint256 tokenId = totalSupply() + 1;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    function burn(uint256 tokenId) external onlyAdmin {
        _burn(tokenId);
    }

}
