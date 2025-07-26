import os
import onnxruntime as ort
import numpy as np
from onnxruntime.quantization import quantize_static, CalibrationDataReader, QuantType
from PIL import Image

def print_model_info(model_path, model_name):
    print(f"\nInspecting {model_name} model: {model_path}")
    try:
        session = ort.InferenceSession(model_path)
        input_details = [(inp.name, inp.shape, inp.type) for inp in session.get_inputs()]
        output_details = [(out.name, out.shape, out.type) for out in session.get_outputs()]
        
        print(f"{model_name} Model Inputs:")
        for name, shape, dtype in input_details:
            print(f"  - Name: {name}, Shape: {shape}, Type: {dtype}")
        
        print(f"{model_name} Model Outputs:")
        for name, shape, dtype in output_details:
            print(f"  - Name: {name}, Shape: {shape}, Type: {dtype}")
    except Exception as e:
        print(f"Error inspecting {model_name} model: {str(e)}")

class DataReader(CalibrationDataReader):
    def __init__(self, image_folder, input_name):
        self.image_folder = image_folder
        self.image_list = [f for f in os.listdir(image_folder) if f.endswith(('.jpg', '.jpeg', '.png'))]
        self.current_index = 0
        self.input_name = input_name
    
    def get_next(self):
        if self.current_index >= len(self.image_list):
            return None
        
        image_path = os.path.join(self.image_folder, self.image_list[self.current_index])
        print(f"Processing image: {image_path}")
        self.current_index += 1
        
        image = Image.open(image_path).convert('RGB')
        image = image.resize((112, 112))
        img_data = np.array(image).astype(np.float32) / 255.0
        # Transform from NHWC to NCHW format
        img_data = np.transpose(img_data, (2, 0, 1))  # CHW
        img_data = np.expand_dims(img_data, axis=0)    # NCHW
        
        print(f"Image shape after processing: {img_data.shape}")
        return {self.input_name: img_data}

    def rewind(self):
        self.current_index = 0

def main():
    input_model_path = "subnet.onnx"
    output_model_path = "subnet_quantized.onnx"
    calibration_dataset_path = "./test_images/"
    
    if not os.path.exists(calibration_dataset_path):
        raise FileNotFoundError(f"Dataset path {calibration_dataset_path} does not exist")
    
    print_model_info(input_model_path, "Original")
    
    session = ort.InferenceSession(input_model_path)
    input_name = session.get_inputs()[0].name
    print(f"Using input name: {input_name}")
    
    dr = DataReader(calibration_dataset_path, input_name)
    
    try:
        
        extras = {
        'ActivationSymmetric': True,  # Make activation quantization symmetric
        'WeightSymmetric': True,      # Make weight quantization symmetric
        'CalibTensorRangeSymmetric': True  # Make calibration range symmetric
        }

        quantize_static(
            model_input=input_model_path,
            model_output=output_model_path,
            calibration_data_reader=dr,
            per_channel=False,
            reduce_range=True,
            activation_type=QuantType.QUInt8,
            weight_type=QuantType.QUInt8, 
            optimize_model=False,
            extra_options=extras,
        )
        
        print("Quantization completed successfully")
        if os.path.exists(output_model_path):
            print("Quantized model successfully created")
            print_model_info(output_model_path, "Quantized")
        else:
            print("Error: Quantized model was not created!")
    except Exception as e:
        print(f"Error during quantization: {str(e)}")

if __name__ == "__main__":
    main()