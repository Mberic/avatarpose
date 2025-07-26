from PIL import Image
import numpy as np
from scipy import ndimage

def thinning(image):
    # Convert the image to binary (0 and 1)
    threshold = 127
    binary = (image > threshold).astype(np.uint8)

    def conditions(image):
        kernel = np.array([[8, 4, 2],
                         [16, 0, 1],
                         [32, 64, 128]], dtype=np.uint8)
        
        neighbors = ndimage.convolve(image, kernel, mode='constant')
        removal = np.zeros_like(image)
        
        for iter_num in range(2):
            p2, p3, p4, p5, p6, p7, p8, p9 = [(neighbors & (1 << i)) >> i for i in range(8)]
            p1 = image

            condition0 = p1 > 0  # Point must be foreground
            neighbor_sum = p2 + p3 + p4 + p5 + p6 + p7 + p8 + p9
            condition1 = (neighbor_sum >= 2) & (neighbor_sum <= 6)
            
            # Calculate transitions
            transitions = np.zeros_like(p1)
            patterns = [p2, p3, p4, p5, p6, p7, p8, p9, p2]  # p2 repeated to check p9->p2
            for i in range(8):
                transitions += ((patterns[i] == 0) & (patterns[i+1] == 1)).astype(np.uint8)
            condition2 = transitions == 1
            
            if iter_num == 0:
                condition3 = ~((p2 & p4 & p6).astype(bool))
                condition4 = ~((p4 & p6 & p8).astype(bool))
            else:
                condition3 = ~((p2 & p4 & p8).astype(bool))
                condition4 = ~((p2 & p6 & p8).astype(bool))

            removal |= (condition0 & condition1 & condition2 & condition3 & condition4)
            
            if iter_num == 0:
                image = np.where(removal, 0, image)
                removal = np.zeros_like(image)
                neighbors = ndimage.convolve(image, kernel, mode='constant')

        return removal

    # Iteratively thin the image
    prev_image = np.zeros_like(binary)
    current_image = binary.copy()

    while not np.array_equal(prev_image, current_image):
        prev_image = current_image.copy()
        pixels_to_remove = conditions(current_image)
        current_image[pixels_to_remove] = 0

    return current_image * 255

def main():
    try:
        # Read the image
        image = Image.open('image.jpeg').convert('L')  # Convert to grayscale
        
        # Convert to numpy array
        img_array = np.array(image)
        
        # Apply thinning
        thinned = thinning(img_array)
        
        # Convert back to PIL Image
        original_image = Image.fromarray(img_array)
        thinned_image = Image.fromarray(thinned.astype(np.uint8))
        
        # Save results
        original_image.save('original.jpg')
        thinned_image.save('thinned.jpg')
        
        # Display results
        original_image.show(title='Original')
        thinned_image.show(title='Thinned')
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
