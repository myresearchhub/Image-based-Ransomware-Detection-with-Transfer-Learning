import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Create directories if they don't exist
directories = ['R', 'B']
for directory in directories:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Read the CSV file
df = pd.read_csv('output.csv')

# Iterate over each row in the DataFrame
for idx, row in enumerate(df.itertuples(), 1):
    # Extract data from the row (excluding the first column)
    data = row[1:]

    
    # Convert data to numpy array
    data = np.array(data, dtype=float)
    
    # Reshape the data into a 2D array (e.g., for image with 10x5 pixels)
    image_data = data.reshape((10, 10))  # Change the shape according to your data

    # Create an image from the data
    plt.imshow(image_data, cmap='rainbow')  # 'rainbow' colormap for colorful image
    plt.axis('off')  # Turn off axis

    # Save the image with a sequential filename in different directories based on index range
    if idx>94 and idx<595:
        directory = 'B'
        print(idx)
    else:
        directory = 'R'

    plt.savefig(f"{directory}/{idx}.png", bbox_inches='tight')  # Save as PNG with tight bounding box
    plt.close()  # Close the figure to avoid memory leaks
