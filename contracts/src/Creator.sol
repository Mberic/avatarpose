// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Creator is ERC721Upgradeable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuard {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant URI_SETTER_ROLE = keccak256("URI_SETTER_ROLE");

    uint256 public constant MAX_SUPPLY = 1_000_000;
    uint256 public creatorRegistrationFee = 12_000 * 10**6;

    uint256 private _nextTokenId;
    string private _customBaseURI;

    IERC20 public paymentToken;
    using Strings for uint256;

    uint256 public constant CREATOR_MINT_ALLOWANCE = 500;
    mapping(address => uint256) private _creatorMintCount;
    mapping(uint256 => string) private _tokenURIs;
    mapping(address => uint32[]) private _creatorTokenIds;

    // Events
    event BaseURIUpdated(string newURI);
    event TokenURISet(uint256 indexed tokenId, string uri);
    event PaymentReceived(address indexed from, uint256 amount);
    event PaymentWithdrawn(address indexed to, uint256 amount);
    event CreatorAdded(address indexed creator);
    event CreatorRegistrationFeeReceived(address indexed creator, uint256 amount);
    event MintPriceUpdated(address indexed creator, uint256 oldPrice, uint256 newPrice);
    event RegistrationFeeUpdated(uint256 oldFee, uint256 newFee);
    event TokenMinted(address indexed creator, address indexed to, uint256 indexed tokenId);

    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory name,
        string memory symbol,
        address initialAdmin,
        string memory baseURI,
        address tokenAddress
    ) public initializer {
        paymentToken = IERC20(tokenAddress);
        _customBaseURI = baseURI;

        __ERC721_init(name, symbol);
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ADMIN_ROLE, initialAdmin);
        _grantRole(URI_SETTER_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
    }

    function mint(address to, string memory uri) public onlyRole(MINTER_ROLE) nonReentrant {
        require(_nextTokenId < MAX_SUPPLY, "Max supply reached");
        require(_creatorMintCount[msg.sender] < CREATOR_MINT_ALLOWANCE, "Creator mint allowance exceeded");
        
        uint256 tokenId = _nextTokenId;
        _nextTokenId++;
        
        _safeMint(to, tokenId);
        _creatorMintCount[msg.sender]++;
        _creatorTokenIds[msg.sender].push(uint32(tokenId));
        
        if (bytes(uri).length > 0) {
            _setTokenURI(tokenId, uri);
        }

        emit TokenMinted(msg.sender, to, tokenId);
    }

    function addCreator(address creatorAddress) public onlyRole(ADMIN_ROLE) {
        _addCreator(creatorAddress);
    }

    function addCreatorWithFee(address creatorAddress) public nonReentrant {
        require(
            paymentToken.transferFrom(msg.sender, address(this), creatorRegistrationFee),
            "Creator registration fee payment failed"
        );

         require(creatorAddress != address(0), "Invalid creator address");
        
        _grantRole(MINTER_ROLE, creatorAddress);

        _addCreator(creatorAddress);
        emit CreatorRegistrationFeeReceived(creatorAddress, creatorRegistrationFee);
    }

    function _addCreator(address creatorAddress) internal {
        require(creatorAddress != address(0), "Invalid creator address");
        
        _grantRole(MINTER_ROLE, creatorAddress);

        emit CreatorAdded(creatorAddress);
    }

    function updateRegistrationFee(uint256 newRegistrationFee) public onlyRole(ADMIN_ROLE) {
        
        uint256 oldFee = creatorRegistrationFee;
        creatorRegistrationFee = newRegistrationFee;
        emit RegistrationFeeUpdated(oldFee, newRegistrationFee);
    }


    function getCreatorTokenIds(address creator) public view returns (uint32[] memory) {
        return _creatorTokenIds[creator];
    }

    function getCreatorMintCount(address creator) public view returns (uint256) {
        return _creatorMintCount[creator];
    }

    function getRemainingMints(address creator) public view returns (uint256) {
        return CREATOR_MINT_ALLOWANCE - _creatorMintCount[creator];
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);

        string memory _tokenURI = _tokenURIs[tokenId];
        if (bytes(_tokenURI).length > 0) {
            return _tokenURI;
        }

        return string(abi.encodePacked(_customBaseURI, tokenId.toString(), ".json"));
    }

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal {
        _tokenURIs[tokenId] = _tokenURI;
        emit TokenURISet(tokenId, _tokenURI);
    }

    function setBaseURI(string memory newURI) public onlyRole(URI_SETTER_ROLE) {
        _customBaseURI = newURI;
        emit BaseURIUpdated(newURI);
    }

    function setTokenURI(uint256 tokenId, string memory newURI) public onlyRole(URI_SETTER_ROLE) {
        require(_exists(tokenId), "Nonexistent token");
        _setTokenURI(tokenId, newURI);
    }

    function _exists(uint256 tokenId) internal view returns (bool) {
        return _ownerOf(tokenId) != address(0);
    }

    function withdraw() public onlyRole(ADMIN_ROLE) nonReentrant {
        uint256 balance = paymentToken.balanceOf(address(this));
        require(balance > 0, "No funds to withdraw");

        emit PaymentWithdrawn(msg.sender, balance);
        require(paymentToken.transfer(msg.sender, balance), "Token transfer failed");
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {}

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
