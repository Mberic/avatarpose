import numpy as np
import json

def format_data(proof_file, output_file):
    # Load JSON and extract rescaled_outputs
    with open(proof_file, 'r') as f:
        proof = json.load(f)

    # Flatten the rescaled_outputs
    rescaled_outputs_nested = proof['pretty_public_inputs']['rescaled_outputs']
    flat_values = [float(x) for sublist in rescaled_outputs_nested for x in sublist]
    arr = np.array(flat_values)
    
    # Define tensor shapes and names - Reordered to match EZKL's expectation
    tensor_info = [
        {'name': '223', 'shape': (1, 32, 14, 14)},
        {'name': '224', 'shape': (1, 64, 14, 14)},
        {'name': '183', 'shape': (1, 16, 56, 56)}
    ]
    
    # Split and reshape data into tensors
    tensors = []
    start_indices = {
        '223': 12544,
        '224': 0,
        '183': 12544 + 6272
    }
    
    for info in tensor_info:
        name = info['name']
        shape = info['shape']
        size = np.prod(shape)
        start = start_indices[name]
        
        print(f"\nDEBUG: Processing tensor {name}")
        print(f"DEBUG: Shape: {shape}, Size: {size}, Start index: {start}")
        
        tensor_data = arr[start:start + size]
        tensor_data = tensor_data.reshape(shape)
        tensor_list = [f"{x:g}" for x in tensor_data.flatten()]
        print(f"DEBUG: First few values: {tensor_list[:5]}")
        
        tensors.append(tensor_list)
    
    # Create the output string
    output = '{"input_data":[[' + '],['.join(','.join(tensor) for tensor in tensors) + ']]}'
    
    # Write to file without newlines
    with open(output_file, 'w') as f:
        f.write(output)
    
    print("\nVerification:")
    for info in tensor_info:
        print(f"Tensor {info['name']}: {info['shape']} = {np.prod(info['shape'])} elements")

# Run the script
format_data('proof.json', 'output1.json')
