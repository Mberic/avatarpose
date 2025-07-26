## Demo

This section is meant to help you understand how to deploy the verifier contract on your  own & then use it for verification. 

To verify, simply run: `node verify.js`. Ensure you have `ethers.js` installed.

```sh
npm i ethers@5.7.2
```

Now,to understand what's happening:

1. Inference

Get the outputs of `proof-submodel1.json`. These are the inputs for submodel2(labelled `network.onnx` in this dir). 

```sh
# this produces output1.json
python3 handle_data.py
```

Use this `output1.json` as data for inference. Go through the standard steps on ezkl:

```sh
# creates settings.json 
gen-settings 

# generates compiled model
compile-circuit

# generates witness
gen-witness 

# generates vk and pk
setup

# generates proof.json
prove
```

2. Proving on the blockchain

Generate the proof call data and Halo2Verifier contract using these Ezkl commands:

```
encode-evm-calldata
create-evm-verifier
```

Download the `calldata.bytes`, `evm_deploy.sol`  and `proof.json`. Deploy evm_deploy.sol contract. 

Get the instances in the proof.json:

```sh
python3 instances2decimal.py
```

Now you have the 2 parameters required for proof verification:

```sh
node verify.js
```
