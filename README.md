# Assignment 3 - Cryptographic Weakness Detection and Side-Channel Resilience

This submission implements the 13 technical tasks in the assignment through a reproducible multimodal framework.

## Included
- `report/IDS_Assignment3_Technical_Report.docx` - complete technical report.
- `run_all.py` - one-command pipeline.
- `src/` - data generation/loading logic, randomness tests, SSP, CPA, hybrid model and plots.
- `outputs/tables/` - all result tables in CSV format.
- `outputs/figures/` - report-ready graphs.
- `models/hybrid_crypto_model.pt` - trained PyTorch model checkpoint.
- `data/processed/demo_multimodal.npz` - reproducible demonstration dataset.

## Run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python run_all.py
```

## Dataset modes
The included execution uses an academically transparent demonstration dataset that follows the ASCAD-style structure: power traces, plaintext metadata, labels, and AES ciphertext. It creates two system profiles: low-leakage CBC and vulnerable ECB with strong Hamming-weight leakage. This allows the complete pipeline to run without distributing multi-gigabyte third-party datasets.

For a real experiment, place ASCAD/ChipWhisperer trace files and ciphertext corpora in `data/raw/`, then adapt the loader according to the field names. The statistical, CPA, model and reporting modules remain unchanged.

## Reproducibility
The random seed is fixed in `config.yaml`. The pipeline exports the train/validation/test results, CPA key ranking, CRI values, SSP tables, and publication-ready figures.
