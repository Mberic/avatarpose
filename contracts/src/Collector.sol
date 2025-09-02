// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract Collector is ERC721, AccessControl, ReentrancyGuard {
    // Define roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant URI_SETTER_ROLE = keccak256("URI_SETTER_ROLE");

    uint256 private _nextTokenId;

    IERC20 public paymentToken;
    uint256 public mintPrice = 20 * 10**6; // 20 tokens (assuming 6 decimals)

    mapping(uint256 => string) private _tokenURIs;
    mapping(address => uint256) public minterAllowance;
    using Strings for uint256;

    // Events
    event TokenURISet(uint256 indexed tokenId, string uri);
    event PaymentReceived(address indexed from, uint256 amount);
    event PaymentWithdrawn(address indexed to, uint256 amount);
    event MinterRoleGranted(address indexed account, uint256 allowance);
    event MinterRoleRevoked(address indexed account);

    constructor(string memory name, string memory symbol, address initialAdmin, address tokenAddress)
        ERC721(name, symbol)
    {
        paymentToken = IERC20(tokenAddress);

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(URI_SETTER_ROLE, initialAdmin);
        minterAllowance[initialAdmin] = 1000;
    }

    function safeMint(address to, string memory newTokenURI)
        public
        onlyRole(MINTER_ROLE)
        returns (uint256)
    {
        require(minterAllowance[msg.sender] > 0, "Minter allowance exceeded");

        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, newTokenURI);

        minterAllowance[msg.sender]--;

        return tokenId;
    }

    function mint(string memory newTokenURI) public nonReentrant returns (uint256) {
        require(
            paymentToken.transferFrom(msg.sender, address(this), mintPrice),
            "Token payment failed"
        );

        uint256 tokenId = _nextTokenId++;
        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, newTokenURI);

        emit PaymentReceived(msg.sender, mintPrice);

        return tokenId;
    }

   function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory _tokenURI = _tokenURIs[tokenId];

        if (bytes(_tokenURI).length > 0) {
            return _tokenURI;
        }

        // fallback to default ERC721 behavior (baseURI + tokenId)
        string memory base = _baseURI();
        return bytes(base).length > 0 ? string(abi.encodePacked(base, tokenId.toString())) : "";
    }


    function setMintPrice(uint256 newPrice) public onlyRole(ADMIN_ROLE) {
        mintPrice = newPrice;
    }

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal {
        _tokenURIs[tokenId] = _tokenURI;
        emit TokenURISet(tokenId, _tokenURI);
    }

    function setTokenURI(uint256 tokenId, string memory newURI) public onlyRole(URI_SETTER_ROLE) {
        require(_exists(tokenId), "URI set for nonexistent token");
        _setTokenURI(tokenId, newURI);
    }

    function _exists(uint256 tokenId) internal view returns (bool) {
        return _ownerOf(tokenId) != address(0);
    }

    function withdraw() public onlyRole(ADMIN_ROLE) nonReentrant {
        uint256 balance = paymentToken.balanceOf(address(this));
        require(balance > 0, "No funds to withdraw");

        address admin = msg.sender;

        emit PaymentWithdrawn(admin, balance);
        require(paymentToken.transfer(admin, balance), "Token transfer failed");
    }

    function grantMinterRole(address account, uint256 allowance) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(MINTER_ROLE, account);
        minterAllowance[account] = allowance;
        emit MinterRoleGranted(account, allowance);
    }

    function revokeMinterRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(MINTER_ROLE, account);
        minterAllowance[account] = 0;
        emit MinterRoleRevoked(account);
    }

    function grantUriSetterRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(URI_SETTER_ROLE, account);
    }

    function revokeUriSetterRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(URI_SETTER_ROLE, account);
    }

    function grantAdminRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(ADMIN_ROLE, account);
    }

    function revokeAdminRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(ADMIN_ROLE, account);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

}