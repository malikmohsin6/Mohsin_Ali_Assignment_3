# Mohsin Ali Assignment 3

## IDS Assignment 3: SSP and AI-Based Cryptanalysis

This repository contains the complete solution for IDS Assignment 3.

## Submission Contents

- Source code: `Source Code/IDS_Assignment3.py`
- Word report: `Report/IDS_Assignment3_Technical_Report.docx`
- PDF report: `Report/IDS_Assignment3.pdf`
- Results: `results/`
- Dataset instructions: `DATASET_INSTRUCTIONS.md`
- Python requirements: `requirements.txt`

## Repository Structure

```text
Mohsin_Ali_Assignment_3/
├── README.txt
├── requirements.txt
├── DATASET_INSTRUCTIONS.md
├── Source Code/
│   └── IDS_Assignment3.py
├── Report/
│   ├── IDS_Assignment3_Technical_Report.docx
│   └── IDS_Assignment3.pdf
├── results/
│   ├── figures/
│   ├── tables/
│   └── models/
└── data/
    └── processed/
```

## Installation

```bash
pip install -r requirements.txt
```

## How to Run

Run complete experiment:

```bash
python "Source Code/IDS_Assignment3.py" --mode all --root .
```

Run quick test:

```bash
python "Source Code/IDS_Assignment3.py" --mode all --quick --root .
```

Run analysis only:

```bash
python "Source Code/IDS_Assignment3.py" --mode analysis --root .
```

Generate report outputs only:

```bash
python "Source Code/IDS_Assignment3.py" --mode report --root .
```

## Dataset Note

Large third-party datasets are not included in this repository. Dataset placement instructions are available in `DATASET_INSTRUCTIONS.md`.

## Academic Note

This project is prepared for the Intrusion Detection Systems course assignment and is intended for academic use only.
