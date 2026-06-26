IDS ASSIGNMENT 3 - MERGED SOURCE PACKAGE
========================================

All Python source code has been merged into one file:
    IDS_Assignment3_All_In_One.py

Install:
    python -m venv .venv
    .venv\Scripts\activate          (Windows)
    source .venv/bin/activate          (Linux/macOS)
    pip install -r requirements.txt

Run the complete analysis and create the Word report:
    python IDS_Assignment3_All_In_One.py --mode all

Fast verification run:
    python IDS_Assignment3_All_In_One.py --mode all --quick

Other modes:
    python IDS_Assignment3_All_In_One.py --mode analysis
    python IDS_Assignment3_All_In_One.py --mode report

Generated folders:
    data/processed     generated multimodal data
    outputs/tables     SSP, randomness, CPA, AI, and CRI tables
    outputs/figures    all graphs
    models             trained PyTorch model
    report             MS Word technical report

Optional overrides:
    --samples 1600 --epochs 8 --batch-size 64 --learning-rate 0.001

Real data loaders are included in the same Python file as load_ascad_h5() and
load_ciphertext_corpus(). Public third-party datasets are not redistributed.
