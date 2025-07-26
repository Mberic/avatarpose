import json
from decimal import Decimal

# Solidity uint256 max value (2^256 - 1)
UINT256_MAX = 2**256 - 1

def hex_to_decimal(hex_str):
    if not hex_str:
        return "0"
    
    try:
        hex_str = hex_str.lower().strip('0x').strip()
        
        if not hex_str:
            return "0"
        
        decimal_value = int(hex_str, 16)
        
        # Check if value exceeds uint256 max
        if decimal_value > UINT256_MAX:
            raise ValueError(f"Value {decimal_value} exceeds Solidity uint256 maximum value ({UINT256_MAX})")
        
        if decimal_value == 0:
            return "0"
            
        # Convert to plain decimal string
        return str(decimal_value)
    except ValueError as ve:
        print(f"Error: {ve}")
        raise
    except Exception as e:
        print(f"Warning: Could not convert value: {hex_str}")
        return "0"

def process_instances():
    try:
        with open('proof.json', 'r') as file:
            data = json.load(file)
        
        if not data.get('instances') or not data['instances'][0]:
            print("Error: No instances found in proof.json")
            return
        
        instances = data['instances'][0]
        
        decimal_instances = []
        for instance in instances:
            if instance:
                decimal_instances.append(hex_to_decimal(instance))
        
        # Write to instances_decimal.txt as a single line with commas
        with open('instances_decimal.txt', 'w') as file:
            file.write('[' + ','.join(decimal_instances) + ']')
                
        print("Conversion completed successfully!")
        
    except FileNotFoundError:
        print("Error: proof.json file not found")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in proof.json")
    except ValueError as ve:
        print(f"Error: {ve}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    # process_instances()  # Use this for proof.json
    process_instances()  
