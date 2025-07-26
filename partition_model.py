import onnx
from onnx import helper, shape_inference
import copy
import numpy as np

def print_tensor_info(model):
    print("\nModel Info:")
    print("Input shapes:")
    for input in model.graph.input:
        shape = [dim.dim_value for dim in input.type.tensor_type.shape.dim]
        print(f"  {input.name}: {shape}")
    print("Output shapes:")
    for output in model.graph.output:
        shape = [dim.dim_value for dim in output.type.tensor_type.shape.dim]
        print(f"  {output.name}: {shape}")

def split_onnx_model(input_model, split_node, output_model1, output_model2):
    model = onnx.load(input_model)
    graph = model.graph

    print("\nOriginal Model Info:")
    print_tensor_info(model)

    # Find split node index
    split_index = next((i for i, node in enumerate(graph.node) if node.name == split_node), None)
    if split_index is None:
        raise ValueError(f"Node {split_node} not found in the model.")

    # First submodel (Input → Split Node)
    nodes_1 = graph.node[:split_index + 1]
    split_node_output = nodes_1[-1].output[0]

    # Track all outputs and their shapes from first submodel that are needed by second submodel
    outputs_1 = set()
    needed_outputs = set()
    output_shapes = {}

    # Collect all outputs from first submodel
    for node in nodes_1:
        outputs_1.update(node.output)

    # Find which outputs are needed by second submodel
    for node in graph.node[split_index + 1:]:
        for input_name in node.input:
            if input_name in outputs_1:
                needed_outputs.add(input_name)

    # Get shapes for needed outputs
    for value_info in graph.value_info:
        if value_info.name in needed_outputs:
            output_shapes[value_info.name] = [dim.dim_value for dim in value_info.type.tensor_type.shape.dim]

    # Collect initializers for first submodel
    used_inputs_1 = set()
    for node in nodes_1:
        used_inputs_1.update(node.input)
    
    initializers_1 = []
    for init in graph.initializer:
        if init.name in used_inputs_1:
            initializers_1.append(init)

    # Create output tensors for first submodel
    output_tensors_1 = []
    for output_name in needed_outputs:
        shape = output_shapes.get(output_name)
        if shape is None:
            # If shape not found, try to infer it
            shape = [1, 64, 14, 14] if output_name == split_node_output else [1, 16, 28, 28]
        output_tensors_1.append(
            helper.make_tensor_value_info(output_name, onnx.TensorProto.FLOAT16, shape)
        )

    # Create first submodel
    subgraph_1 = helper.make_graph(
        nodes_1,
        "submodel_1",
        [helper.make_tensor_value_info(graph.input[0].name, onnx.TensorProto.FLOAT16, [1, 3, 112, 112])],
        output_tensors_1,
        initializers_1
    )

    # Second submodel (Split Node → Output)
    nodes_2 = []
    initializers_2 = []

    # Create input tensors for second submodel
    input_tensors_2 = []
    for output_name in needed_outputs:
        shape = output_shapes.get(output_name)
        if shape is None:
            shape = [1, 64, 14, 14] if output_name == split_node_output else [1, 16, 28, 28]
        input_tensors_2.append(
            helper.make_tensor_value_info(output_name, onnx.TensorProto.FLOAT16, shape)
        )

    # Process nodes for second submodel
    for node in graph.node[split_index + 1:]:
        if node.op_type == 'Clip':
            min_val = np.array([0.0], dtype=np.float16)
            max_val = np.array([6.0], dtype=np.float16)
            
            new_node = helper.make_node(
                'Clip',
                inputs=[node.input[0], f"{node.name}_min", f"{node.name}_max"],
                outputs=node.output,
                name=node.name
            )
            
            min_tensor = helper.make_tensor(
                name=f"{node.name}_min",
                data_type=onnx.TensorProto.FLOAT16,
                dims=[1],
                vals=min_val.tobytes(),
                raw=True
            )
            
            max_tensor = helper.make_tensor(
                name=f"{node.name}_max",
                data_type=onnx.TensorProto.FLOAT16,
                dims=[1],
                vals=max_val.tobytes(),
                raw=True
            )
            
            nodes_2.append(new_node)
            initializers_2.extend([min_tensor, max_tensor])
        else:
            nodes_2.append(node)

    # Collect remaining initializers for second submodel
    used_inputs_2 = set()
    for node in nodes_2:
        used_inputs_2.update(node.input)
    
    for init in graph.initializer:
        if init.name in used_inputs_2 and not any(init.name == tensor.name for tensor in initializers_2):
            initializers_2.append(init)

    # Add constant tensors needed by second submodel
    constant_tensors = ['239', '242']
    for const in constant_tensors:
        init = next((x for x in graph.initializer if x.name == const), None)
        if init and not any(init.name == tensor.name for tensor in initializers_2):
            initializers_2.append(init)

    subgraph_2 = helper.make_graph(
        nodes_2,
        "submodel_2",
        input_tensors_2,
        [helper.make_tensor_value_info('output', onnx.TensorProto.FLOAT16, [1, 212, 1, 1])],
        initializers_2
    )

    # Create models with proper metadata
    model_1 = helper.make_model(
        subgraph_1,
        producer_name="ONNX_Partitioner",
        opset_imports=[helper.make_opsetid("", 13)]
    )
    model_2 = helper.make_model(
        subgraph_2,
        producer_name="ONNX_Partitioner",
        opset_imports=[helper.make_opsetid("", 13)]
    )

    # Set IR version
    model_1.ir_version = 7
    model_2.ir_version = 7

    # Perform shape inference and checking
    model_1 = shape_inference.infer_shapes(model_1)
    model_2 = shape_inference.infer_shapes(model_2)

    print("\nSubmodel 1 Info:")
    print_tensor_info(model_1)
    print("\nSubmodel 2 Info:")
    print_tensor_info(model_2)

    onnx.checker.check_model(model_1)
    onnx.checker.check_model(model_2)

    # Save models
    onnx.save(model_1, output_model1)
    onnx.save(model_2, output_model2)

    print(f"\nModels successfully split and saved as {output_model1} and {output_model2}")

# Run the splitting
split_onnx_model("network.onnx", "Conv_43", "submodel1.onnx", "submodel2.onnx")
