# A Novel Technique for Ransomware Detection Using Image-Based Dynamic Features and Transfer Learning: Addressing Dataset Limitations 

## Overview
This study proposes a novel ransomware detection method that combines dynamic analysis with transfer learning. By extracting behaviour-based features from ransomware in a controlled environment and converting them into images, the method leverages pre-trained CNNs for classification. The approach achieves 99.96% accuracy, outperforming traditional models, and provides a robust solution for detecting evolving ransomware variants, even with a limited small dataset.

### Contribution
- Developed a novel approach combining dynamic ransomware behavior data with image classification.
- Achieved 99.96% accuracy on color image datasets and 99.91% accuracy on grayscale datasets.
- Demonstrated that pre-trained models outperform non-pre-trained models, even with a small dataset.
- Showed how domain-based filtering can impact the overall accuracy even on a small dataset.

## Proposed Method
The approach proposed in this project consists of the following key phases:

1. **Dataset Creation**:
   - Collection of 1000 binary executable samples, consisting of 500 benign applications and 500 ransomware samples from 25 distinct ransomware families.
   - The dataset was curated to include ransomware families that are most relevant and impactful, ensuring coverage of high-prevalence and globally significant ransomware types.
  
2. **Dynamic Analysis and Visualization**:
   - Dynamic analysis was performed using **Cuckoo Sandbox**, an isolated environment that monitors real-time ransomware behavior. 
   - Data collected from the analysis (such as process creation, file modifications, network activity) were converted into **CSV** format.
   - A color-mapping technique was then applied to this structured data to convert it into visual representations for CNNs to analyze.

3. **Model Training and Evaluation**:
   - Transfer learning with pre-trained CNN models (ResNet50, EfficientNetB0, Xception, etc.) was employed to classify ransomware behaviors from images generated in the previous step.
   - A range of performance metrics was used to evaluate the models, including **accuracy**, **precision**, **recall**, and **F1-score**.
   - Pre-trained models demonstrated superior performance compared to non-pre-trained models, particularly in handling small, diverse datasets.

### Preprocessing Files
The following files are used for preprocessing and are available in the repository:
1. **`Extract_features.py`**: A Python script for extracting dynamic features from the ransomware samples using **Cuckoo Sandbox**.
2. **`Generate_images_color.py`**: A Python script for converting extracted features into color images for CNN training.
3. **`Generate_images_gray.py`**: A Python script for generating grayscale images from the same dynamic feature data.

### Performance Metrics
- **Accuracy**: 99.96% on color datasets, 99.91% on grayscale datasets.
- **Loss**: Low loss for both types of datasets, indicating good model performance.
- **Other Metrics**: High **precision**, **recall**, and **F1-score** across both ransomware and benign classes.

## Dataset Sources
The samples used for this study were collectd from the following publicly available sources:
- **MalwareBazaar**: For collecting high-impact ransomware samples from known families.
  https://bazaar.abuse.ch/browse/
- **VirusShare**: A trusted source for ransomware data and samples.
  https://virusshare.com/
- **SnapFiles, PortableApps.com, GitHub**: For benign software samples to ensure a balanced dataset.
  https://www.snapfiles.com/freeware/
  
  https://portableapps.com/
  
  https://github.com/iosifache/DikeDataset/tree/main/files/benign
 
## Methodology
![Image](https://github.com/user-attachments/assets/2ed7a6eb-fffa-4428-90fc-45287cf05315)
### 1. Sample Collection and Selection
Ransomware samples were chosen based on the following criteria:
- **High Prevalence**: Samples were selected from ransomware families that have been reported as prevalent in major cybersecurity publications.
- **Impact Analysis**: Only ransomware families with a significant impact on organizations globally were included.
- **Vendor Engine Detection**: Samples were cross-verified using **VirusTotal** to ensure that at least 45 antivirus engines marked them as malicious, with 15 engines identifying them as ransomware.

### 2. Execution and Monitoring
Each ransomware and the benign sample was executed within the **Cuckoo Sandbox**, which provides real-time monitoring of system behaviors. The key type of activities captured included:
- **File Modifications**
- **Process Creation**
- **Network Communications**

These dynamic features were then structured into **CSV** files and color-mapped to generate corresponding images for further analysis.

### 3. Model Training and Evaluation
The pre-trained CNN models were then fine-tuned using the generated image datasets. The models evaluated include:
- **ResNet50**
- **EfficientNetB0**
- **Xception**
- **InceptionV3**
- **VGG16**, **VGG19**
- **CNN-GRU**, **CNN-LSTM**

The models were evaluated based on their ability to classify the ransomware and benign samples accurately, with **ResNet50** emerging as the top performer, achieving a remarkable **99.96% accuracy** on color datasets.

## Results
| Model            | Accuracy (Color Image) | Accuracy (Gray Image) | Difference (%) | Loss (Color Dataset) | Loss (Grayscale Dataset) | Difference (%) |
|------------------|------------------------|-----------------------|----------------|----------------------|--------------------------|----------------|
| **ResNet50**      | 99.96                  | 99.91                 | 0.05           | 0.0026               | 0.0059                   | 0.0033         |
| **EfficientNetB0**| 99.78                  | 99.70                 | 0.08           | 0.0069               | 0.0167                   | 0.0098         |
| **Xception**      | 98.91                  | 98.12                 | 0.79           | 0.0253               | 0.0471                   | 0.0218         |
| **InceptionV3**   | 98.84                  | 98.04                 | 0.80           | 0.0579               | 0.1261                   | 0.0682         |
| **VGG16**         | 97.84                  | 97.60                 | 0.24           | 0.0602               | 0.1179                   | 0.0577         |
| **VGG19**         | 97.47                  | 97.40                 | 0.07           | 0.0874               | 0.1194                   | 0.0320         |
| **CNN-GRU**       | 97.49                  | 97.07                 | 0.42           | 0.0579               | 0.0680                   | 0.0101         |
| **CNN-LSTM**      | 96.94                  | 96.80                 | 0.14           | 0.0963               | 0.0807                   | -0.0156        |
| **CNN**           | 96.84                  | 96.71                 | 0.13           | 0.0998               | 0.1045                   | 0.0047         |
| **ANN**           | 90.48                  | 89.24                 | 1.24           | 0.2707               | 0.2853                   | 0.0146         |
## Future Work
1. **Dataset Expansion**: The dataset will be expanded to include more ransomware families and benign variants, further improving robustness.
2. **Adaptability to New Threats**: The approach will be updated dynamically as new ransomware variants emerge.
3. **Real-World Validation**: The method will be tested with live ransomware samples in production environments to evaluate its practical utility and effectiveness.
4. **Scalability**: Integrating additional models and increasing platform compatibility will allow the system to scale efficiently.

## Dataset
The dataset used in this study comprises dynamic features extracted from ransomware samples. These features were transformed into images for classification. The dataset is currently under the approval process by our university for sharing. Once approved, we will provide a download link here.

## Acknowledgments
- **MalwareBazaar** for providing ransomware samples.
- **VirusTotal** for vendor engine detection data.
- **Cuckoo Sandbox** for dynamic analysis of ransomware behaviors.
  
## Contact
For inquiries or contributions, feel free to reach out to [your email/contact info].

