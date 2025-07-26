const { ethers } = require("ethers");
const abi = require("./foundry/out/Halo2Verifier.sol/Halo2Verifier.json");
const fs = require('fs');

require('dotenv').config();

const HALO2_ADDRESS = "0xbEfBA0f03aD1F4344EDC7aAe14D014CAb8cAc51A";
const PRIVATE_KEY = process.env.PRIVATE_KEY;

const provider = new ethers.providers.JsonRpcProvider(
    "https://testnet.skalenodes.com/v1/aware-fake-trim-testnet",
    {
        name: "skale",
        chainId: 1020352220
    }
);

const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const HALO2_CONTRACT = new ethers.Contract(HALO2_ADDRESS, abi.abi, signer);

async function verify() {
    try {
        // Read the raw calldata
        const calldataBuffer = fs.readFileSync('calldata.bytes');
        const calldata = '0x' + calldataBuffer.toString('hex');

        console.log('Calldata length:', calldata.length);
        console.log('Calldata prefix:', calldata.slice(0, 10));

        // Send the transaction using the low-level sendTransaction
        const txOptions = {
            to: HALO2_ADDRESS,
            data: calldata,
            gasLimit: 250222000,
            gasPrice: await provider.getGasPrice()
        };

        // Try static call first
        console.log('Attempting static call...');
        try {
            const result = await provider.call(txOptions);
            console.log('Static call result:', result);
        } catch (staticError) {
            console.error('Static call failed:', staticError);
        }

        // Send the actual transaction
        console.log('Sending transaction...');
        const tx = await signer.sendTransaction(txOptions);
        console.log('Transaction sent:', tx.hash);
        
        const receipt = await tx.wait();
        console.log('Transaction receipt:', {
            status: receipt.status,
            gasUsed: receipt.gasUsed.toString(),
            blockNumber: receipt.blockNumber
        });

        return receipt.status === 1;

    } catch (error) {
        console.error('Verification Error:', {
            message: error.message,
            code: error.code,
            reason: error.reason,
            data: error.data
        });
        throw error;
    }
}

verify()
    .then(result => {
        console.log('Final verification result:', result);
        process.exit(0);
    })
    .catch(error => {
        console.error('Verification failed with error:', error);
        process.exit(1);
    });
