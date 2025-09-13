// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract EtherFaucet {
    address public owner;
    uint256 public constant DISTRIBUTION_AMOUNT = 0.00001 ether; // 10000 gwei
    uint256 public constant BALANCE_THRESHOLD = 0.000001 ether;  // 1000 gwei (10% of distribution)
    
    // Events
    event FundsDistributed(address indexed recipient, uint256 amount);
    event FaucetFunded(address indexed funder, uint256 amount);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier canClaim() {
        require(msg.sender.balance < BALANCE_THRESHOLD, "Balance too high for claim");
        require(address(this).balance >= DISTRIBUTION_AMOUNT, "Insufficient contract balance");
        _;
    }
    
    constructor() payable {
        owner = msg.sender;
        if (msg.value > 0) {
            emit FaucetFunded(msg.sender, msg.value);
        }
    }
    
    /**
     * @dev Allows users to claim ether if their balance is below threshold
     */
    function claimEther() external canClaim {
        // Transfer ether to the caller
        (bool success, ) = payable(msg.sender).call{value: DISTRIBUTION_AMOUNT}("");
        require(success, "Transfer failed");
        
        emit FundsDistributed(msg.sender, DISTRIBUTION_AMOUNT);
    }
    
    /**
     * @dev Check if an address is eligible to claim
     * @param user The address to check
     * @return eligible True if the user can claim, false otherwise
     * @return reason String explaining why user cannot claim (if applicable)
     */
    function checkEligibility(address user) external view returns (bool eligible, string memory reason) {
        if (user.balance >= BALANCE_THRESHOLD) {
            return (false, "Balance too high");
        }
        
        if (address(this).balance < DISTRIBUTION_AMOUNT) {
            return (false, "Insufficient contract balance");
        }
        
        return (true, "Eligible to claim");
    }
    
    /**
     * @dev Fund the faucet contract
     */
    function fundFaucet() external payable {
        require(msg.value > 0, "Must send ether to fund");
        emit FaucetFunded(msg.sender, msg.value);
    }
    
    /**
     * @dev Withdraw funds from the contract (owner only)
     * @param amount Amount to withdraw in wei
     */
    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "Insufficient balance");
        
        (bool success, ) = payable(owner).call{value: amount}("");
        require(success, "Withdrawal failed");
    }
    
    /**
     * @dev Emergency withdrawal of all funds (owner only)
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = payable(owner).call{value: balance}("");
        require(success, "Emergency withdrawal failed");
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }
    
    /**
     * @dev Get contract balance
     * @return balance Current balance of the contract in wei
     */
    function getContractBalance() external view returns (uint256 balance) {
        return address(this).balance;
    }
    
    /**
     * @dev Get distribution statistics
     * @return distributionAmount Amount distributed per claim
     * @return threshold Balance threshold for eligibility
     */
    function getDistributionInfo() external pure returns (
        uint256 distributionAmount,
        uint256 threshold
    ) {
        return (DISTRIBUTION_AMOUNT, BALANCE_THRESHOLD);
    }
    
    // Allow contract to receive ether
    receive() external payable {
        emit FaucetFunded(msg.sender, msg.value);
    }
    
    fallback() external payable {
        emit FaucetFunded(msg.sender, msg.value);
    }
}