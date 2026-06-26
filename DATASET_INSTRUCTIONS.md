# Using Real Datasets

## ASCAD
1. Obtain the ASCAD database from the official ANSSI ASCAD repository.
2. Place the HDF5 file at `data/raw/ASCAD.h5`.
3. Use `src.real_data_loader.load_ascad_h5()` to read traces and plaintext/key metadata.

## ChipWhisperer / DPA Contest
Export traces to a NumPy matrix (`samples x time-points`) and plaintext bytes to a second NumPy matrix. They can then be passed directly to the SSP and CPA modules.

## Ciphertext corpus
Create a CSV with a `ciphertext` column containing hexadecimal ciphertext, or a TXT file with one hex string per line. Load it with `load_ciphertext_corpus()`.

The repository does not redistribute third-party datasets. The included demo data is small, reproducible, and is intended to verify the complete pipeline before a large-dataset run.
