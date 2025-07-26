import numpy as np
from PIL import Image

def create_ezkl_input(image_path, output_json_path, img_size=112):
    try:
        with Image.open(image_path) as img:
            img = img.convert('L')
            img = img.resize((img_size, img_size))
            
            # Convert to numpy array and normalize to [0,1]
            img_array = np.array(img, dtype=np.float32) / 255.0
            
            # Quantize to 4 bits (16 levels)
            levels = 16  # 2^4
            img_array = np.round(img_array * (levels - 1)) / (levels - 1)
            
            # Duplicate for RGB channels
            img_rgb = np.stack([img_array] * 3, axis=-1)
            
            flattened = img_rgb.reshape(-1).tolist()
            
            input_data = {
                "input_data": [flattened]
            }
            
            print(f"Input length: {len(flattened)}")
            
            import json
            with open(output_json_path, 'w') as f:
                json.dump(input_data, f)
            
            print(f"Created input JSON at {output_json_path}")
            print(f"First few values: {flattened[:5]}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        raise

if __name__ == "__main__":
    image_path = "thinned.jpg"
    output_json_path = "input.json"
    create_ezkl_input(image_path, output_json_path)