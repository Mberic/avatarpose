import json
import numpy as np
from PIL import Image, ImageDraw

def draw_landmarks(proof_path, output_path, size=(112, 112)):
    # Read the proof file
    with open(proof_path, 'r') as f:
        proof_data = json.load(f)
    
    # Print first few raw values for debugging
    raw_values = proof_data['pretty_public_inputs']['rescaled_outputs'][0]
    print("First few raw values:")
    print(raw_values[:10])
    
    # Take pairs of values for x,y coordinates
    values = []
    for i in range(0, len(raw_values), 2):
        if i+1 < len(raw_values):
            x = float(raw_values[i])
            y = float(raw_values[i+1])
            values.append([x, y])
    
    points = np.array(values)
    print("\nFirst few points before transformation:")
    print(points[:5])
    
    # Flip x-coordinates and scale
    points[:, 0] = 1 - points[:, 0]  # Flip horizontally
    points[:, 0] *= size[0]  # Scale to width
    points[:, 1] *= size[1]  # Scale to height
    
    print("\nFirst few points after transformation:")
    print(points[:5])
    
    # Create black background
    img = Image.new('RGB', size, color='black')
    draw = ImageDraw.Draw(img)
    
    # Draw points
    point_size = 1
    for x, y in points.astype(int):
        draw.ellipse([x-point_size, y-point_size, 
                     x+point_size, y+point_size], 
                    fill='white', outline='white')
    
    # Save the result
    img.save(output_path)
    print(f"\nLandmarks visualization saved to {output_path}")

if __name__ == "__main__":
    proof_path = "proof.json"
    output_path = "output.jpeg"
    
    draw_landmarks(proof_path, output_path)
