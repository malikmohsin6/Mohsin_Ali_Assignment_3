# Mohsin Ali Assignment 3

## IDS Assignment 3: Cryptographic System Weakness Detection using SSP and AI

**Course:** Intrusion Detection Systems  
**Course Code:** COMP-995  
**Program:** MS Information Security  
**Institute:** PAK-Austria Fachhochschule, School of Computing  
**Student:** Mohsin Ali  

---

## 1. Project Overview

This repository contains the complete solution for **IDS Assignment 3**.

The assignment theme is:

**Cryptographic System Weakness Detection and Side-Channel Resilience Assessment using Statistical Profiling and AI-Based Cryptanalysis**

The project implements a research-grade framework that analyzes cryptographic system weaknesses using:

- Statistical Analysis Module (SAM)
- Statistical Security Profile (SSP)
- Randomness evaluation
- Entropy and uncertainty analysis
- Side-channel leakage analysis
- AI-based cryptanalysis
- CPA/DPA-style cryptanalysis simulation
- Hybrid AI model
- Cryptographic Risk Index (CRI)
- Results visualization and benchmarking

---

## 2. Repository Structure

```text
Mohsin_Ali_Assignment_3/
│
├── README.txt
├── requirements.txt
├── DATASET_INSTRUCTIONS.md
│
├── Source Code/
│   └── IDS_Assignment3.py
│
├── Report/
│   ├── IDS_Assignment3_Technical_Report.docx
│   └── IDS_Assignment3.pdf
│
├── results/
│   ├── figures/
│   ├── tables/
│   └── models/
│
└── data/
    └── processed/
```

---

## 3. Main Assignment Tasks Covered

The project covers all required Assignment 3 tasks:

1. Real industry problem and challenge
2. Problem statement
3. Research objectives
4. Relevant dataset selection
5. Randomness evaluation
6. Statistical Analysis Module
7. Statistical Security Profile report
8. Research methodology
9. Performance evaluation and benchmarking
10. Results presentation
11. Comparison with state-of-the-art
12. Discussion and analysis
13. Conclusion

---

## 4. Implemented Modules

The source code includes the following major modules:

- Synthetic controlled cryptographic dataset generation
- Real dataset loader support
- Side-channel trace analysis
- Ciphertext statistical analysis
- Randomness testing
- Shannon entropy calculation
- Min-entropy calculation
- Conditional entropy and mutual information
- Frequency/monobit test
- Runs test
- Serial pattern test
- Autocorrelation analysis
- Dataset-level statistics
- Correlation and dependency analysis
- Outlier and anomaly statistics
- Class imbalance analysis
- Feature pre-ranking
- CPA-based key recovery simulation
- Hybrid AI model for cryptographic weakness detection
- Cryptographic Risk Index calculation
- State-of-the-art comparison
- Graph and table generation
- Technical report generation support

---

## 5. Installation

Clone the repository:

```bash
git clone https://github.com/malikmohsin6/Mohsin_Ali_Assignment_3.git
```

Open the repository folder:

```bash
cd Mohsin_Ali_Assignment_3
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

---

## 6. How to Run

### Run the complete experiment

```bash
python "Source Code/IDS_Assignment3.py" --mode all --root .
```

### Run a quick test

```bash
python "Source Code/IDS_Assignment3.py" --mode all --quick --root .
```

### Run analysis only

```bash
python "Source Code/IDS_Assignment3.py" --mode analysis --root .
```

### Generate/update report outputs only

```bash
python "Source Code/IDS_Assignment3.py" --mode report --root .
```

---

## 7. Output Files

After running the code, outputs are generated under the `results` folder.

### Figures

```text
results/figures/
```

This folder contains graphs such as:

- Framework architecture
- Class distribution
- Correlation heatmap
- Entropy graph
- Feature ranking
- Confusion matrix
- ROC curve
- Model accuracy curve
- Model loss curve
- CPA key score graph
- Key-rank curve
- CRI distribution
- Side-channel trace profile

### Tables

```text
results/tables/
```

This folder contains CSV outputs such as:

- Dataset statistics
- Randomness evaluation
- Feature ranking
- Correlation matrix
- Class imbalance profile
- CPA key hypotheses
- Model metrics
- Confusion matrix
- Cross-dataset results
- CRI results
- State-of-the-art comparison
- Training history

### Models

```text
results/models/
```

This folder contains the trained model file:

```text
hybrid_crypto_model.pt
```

---

## 8. Dataset Notes

Large third-party datasets are not redistributed in this repository.

The code supports controlled proxy data for reproducible testing. It can also be extended to real public datasets such as:

- ASCAD Dataset
- DPA Contest Dataset
- ChipWhisperer Dataset
- CrypTool ciphertext corpus
- Other relevant cryptanalysis and ciphertext datasets

Dataset placement and usage instructions are available in:

```text
DATASET_INSTRUCTIONS.md
```

---

## 9. Report Files

The technical report is available in the `Report` folder.

```text
Report/IDS_Assignment3_Technical_Report.docx
Report/IDS_Assignment3.pdf
```

The `.docx` file is the main MS Word technical report for submission.  
The `.pdf` file is included as a reading copy.

---

## 10. Requirements

The main Python packages used in this project include:

- numpy
- pandas
- scipy
- scikit-learn
- matplotlib
- h5py
- cryptography
- torch
- python-docx

All required packages are listed in:

```text
requirements.txt
```

---

## 11. Reproducibility

The project uses controlled reference experiments so that the code can run without downloading large external datasets. This makes the results reproducible for academic checking.

To reproduce the main outputs:

```bash
python "Source Code/IDS_Assignment3.py" --mode all --root .
```

For faster verification:

```bash
python "Source Code/IDS_Assignment3.py" --mode all --quick --root .
```

---

## 12. Submission Contents

This repository contains:

- Complete source code
- MS Word technical report
- PDF reading copy
- Result tables
- Result figures
- Trained model file
- Dataset instructions
- Python requirements file

---

## 13. Disclaimer

This project is prepared for academic purposes as part of the Intrusion Detection Systems course assignment. The controlled datasets and outputs are used for reproducible demonstration. Real-world deployment requires validation on original datasets and operational cryptographic environments.
