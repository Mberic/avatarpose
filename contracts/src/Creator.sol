// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Creator is ERC721, AccessControl, ReentrancyGuard {
    // Define roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant URI_SETTER_ROLE = keccak256("URI_SETTER_ROLE");

    // Constants for creator allocation
    uint256 public constant MAX_SUPPLY = 15000;
    uint256 public constant MAX_CREATORS = 20;
    uint256 public constant NFTS_PER_CREATOR = 500;
    uint256 public constant CREATOR_REGISTRATION_FEE = 15000 * 10**6; // 15,000 USDT (6 decimals)

    uint256 private _nextTokenId;
    mapping(uint256 => string) private _tokenURIs;
    string private _customBaseURI;

    IERC20 public paymentToken;

    // Creator management
    struct CreatorInfo {
        address account;
        uint256 startTokenId;
        uint256 endTokenId;
        uint256 mintedCount;
        uint256 mintPrice;
        bool isActive;
    }

    mapping(address => CreatorInfo) public creators;
    address[] public creatorList;
    uint256 public creatorCount;

    // Events
    event BaseURIUpdated(string newURI);
    event TokenURISet(uint256 indexed tokenId, string uri);
    event PaymentReceived(address indexed from, uint256 amount);
    event PaymentWithdrawn(address indexed to, uint256 amount);
    event CreatorAdded(address indexed creator, uint256 startTokenId, uint256 endTokenId, uint256 mintPrice);
    event CreatorMintPriceUpdated(address indexed creator, uint256 oldPrice, uint256 newPrice);
    event CreatorRegistrationFeeReceived(address indexed creator, uint256 amount);

    constructor(string memory name, string memory symbol, address initialAdmin, string memory baseURI, address tokenAddress)
        ERC721(name, symbol)
    {
        _customBaseURI = baseURI;
        paymentToken = IERC20(tokenAddress);

        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(ADMIN_ROLE, initialAdmin);
        _grantRole(URI_SETTER_ROLE, initialAdmin);
        // Note: Admin doesn't get MINTER_ROLE at deployment as per requirement
    }

    // Admin can add creator without paying fee
    function addCreator(address creatorAddress, uint256 mintPrice) public onlyRole(ADMIN_ROLE) {
        _addCreator(creatorAddress, mintPrice);
    }

    // Anyone can add creator by paying the registration fee
    function addCreatorWithFee(address creatorAddress, uint256 mintPrice) public nonReentrant {
        require(
            paymentToken.transferFrom(msg.sender, address(this), CREATOR_REGISTRATION_FEE),
            "Creator registration fee payment failed"
        );
        
        emit CreatorRegistrationFeeReceived(creatorAddress, CREATOR_REGISTRATION_FEE);
        _addCreator(creatorAddress, mintPrice);
    }

    // Internal function to handle creator addition logic
    function _addCreator(address creatorAddress, uint256 mintPrice) internal {
        require(creatorAddress != address(0), "Invalid creator address");
        require(!creators[creatorAddress].isActive, "Creator already exists");
        require(creatorCount < MAX_CREATORS, "Maximum creators reached");
        require(mintPrice > 0, "Mint price must be greater than 0");

        uint256 startTokenId = creatorCount * NFTS_PER_CREATOR;
        uint256 endTokenId = startTokenId + NFTS_PER_CREATOR - 1;

        creators[creatorAddress] = CreatorInfo({
            account: creatorAddress,
            startTokenId: startTokenId,
            endTokenId: endTokenId,
            mintedCount: 0,
            mintPrice: mintPrice,
            isActive: true
        });

        creatorList.push(creatorAddress);
        creatorCount++;

        _grantRole(MINTER_ROLE, creatorAddress);

        emit CreatorAdded(creatorAddress, startTokenId, endTokenId, mintPrice);
    }

    // Creator can update their own mint price
    function updateMyMintPrice(uint256 newMintPrice) public {
        require(creators[msg.sender].isActive, "You are not an active creator");
        require(newMintPrice > 0, "Mint price must be greater than 0");
        
        uint256 oldPrice = creators[msg.sender].mintPrice;
        creators[msg.sender].mintPrice = newMintPrice;
        
        emit CreatorMintPriceUpdated(msg.sender, oldPrice, newMintPrice);
    }

    function creatorMint(address to, string memory newTokenURI)
        public
        onlyRole(MINTER_ROLE)
        nonReentrant
        returns (uint256)
    {
        CreatorInfo storage creator = creators[msg.sender];
        require(creator.isActive, "Creator not active");
        require(creator.mintedCount < NFTS_PER_CREATOR, "Creator allowance exceeded");

        // Charge the creator's specific mint price
        require(
            paymentToken.transferFrom(msg.sender, address(this), creator.mintPrice),
            "Token payment failed"
        );

        uint256 tokenId = creator.startTokenId + creator.mintedCount;
        require(tokenId <= creator.endTokenId, "Token ID out of range");
        require(tokenId < MAX_SUPPLY, "Max supply exceeded");

        _safeMint(to, tokenId);
        _setTokenURI(tokenId, newTokenURI);
        creator.mintedCount++;

        // Update global next token ID if necessary
        if (tokenId >= _nextTokenId) {
            _nextTokenId = tokenId + 1;
        }

        emit PaymentReceived(msg.sender, creator.mintPrice);

        return tokenId;
    }

    function mint(address creatorAddress, string memory newTokenURI) public nonReentrant returns (uint256) {
        CreatorInfo storage creator = creators[creatorAddress];
        require(creator.isActive, "Creator not active");
        require(creator.mintedCount < NFTS_PER_CREATOR, "Creator allowance exceeded");

        // Use the creator's specific mint price
        require(
            paymentToken.transferFrom(msg.sender, address(this), creator.mintPrice),
            "Token payment failed"
        );

        uint256 tokenId = creator.startTokenId + creator.mintedCount;
        require(tokenId <= creator.endTokenId, "Token ID out of range");
        require(tokenId < MAX_SUPPLY, "Max supply exceeded");

        _safeMint(msg.sender, tokenId);
        _setTokenURI(tokenId, newTokenURI);
        creator.mintedCount++;

        // Update global next token ID if necessary
        if (tokenId >= _nextTokenId) {
            _nextTokenId = tokenId + 1;
        }

        emit PaymentReceived(msg.sender, creator.mintPrice);

        return tokenId;
    }

    function getAvailableCreators() public view returns (
        address[] memory availableCreators,
        uint256[] memory mintPrices,
        uint256[] memory remainingSupply
    ) {
        uint256 count = 0;
        
        // First, count active creators with remaining supply
        for (uint256 i = 0; i < creatorList.length; i++) {
            CreatorInfo memory creator = creators[creatorList[i]];
            if (creator.isActive && creator.mintedCount < NFTS_PER_CREATOR) {
                count++;
            }
        }
        
        // Initialize arrays
        availableCreators = new address[](count);
        mintPrices = new uint256[](count);
        remainingSupply = new uint256[](count);
        
        // Populate arrays
        uint256 index = 0;
        for (uint256 i = 0; i < creatorList.length; i++) {
            CreatorInfo memory creator = creators[creatorList[i]];
            if (creator.isActive && creator.mintedCount < NFTS_PER_CREATOR) {
                availableCreators[index] = creatorList[i];
                mintPrices[index] = creator.mintPrice;
                remainingSupply[index] = NFTS_PER_CREATOR - creator.mintedCount;
                index++;
            }
        }
    }

    function getCreatorInfo(address creatorAddress) public view returns (
        uint256 startTokenId,
        uint256 endTokenId,
        uint256 mintedCount,
        uint256 remainingAllowance,
        uint256 mintPrice,
        bool isActive
    ) {
        CreatorInfo memory creator = creators[creatorAddress];
        return (
            creator.startTokenId,
            creator.endTokenId,
            creator.mintedCount,
            creator.isActive ? NFTS_PER_CREATOR - creator.mintedCount : 0,
            creator.mintPrice,
            creator.isActive
        );
    }

    function getAllCreators() public view returns (address[] memory) {
        return creatorList;
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);

        string memory _tokenURI = _tokenURIs[tokenId];

        if (bytes(_tokenURI).length > 0) {
            return _tokenURI;
        }

        return string(abi.encodePacked(_customBaseURI, toString(tokenId)));
    }

    function toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
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
        require(_exists(tokenId), "URI set of nonexistent token");
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

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
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
}
