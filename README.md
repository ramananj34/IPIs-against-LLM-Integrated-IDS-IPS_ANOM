# Indirect Prompt Injections via Network Protocol Fields against LLM-Integrated IDS/IPS Systems

## Introduction

This project empirically evaluates whether indirect prompt injection attacks, embedded in HTTP header fields, can cause LLM-powered Intrusion Detection Systems (IDS) to misclassify malicious network traffic. Using a modified version of the CSIC 2010 dataset, we construct benign and malicious HTTP traffic samples augmented with a range of prompt injection payloads, and evaluate classification accuracy across multiple LLMs configured to behave as IDS systems. Metrics include Attack Success Rate (ASR), F1, precision, and recall. We also explore whether defensive prompting strategies can mitigate these vulnerabilities.

---

## Dataset Augmentation Pipeline

### Step 1: Obtain the Dataset

Unzip `CSIC2010.zip` and note the path to the database CSV.

**Default path:** `data/csic_database.csv`  
Do **not** commit or push the unzipped dataset to the repository.

---

### Step 2: Preprocess the Dataset

Run the preprocessing tool to produce a balanced sample of benign and malicious HTTP requests, with malicious HTTP requests classified by attack type.

```
python -m augmentation.preprocess <raw_csv_path> <preprocessed_csv_path> <sample_size>
```

- `raw_csv_path` - path to the raw dataset CSV from Step 1 (default: `data/csic_database.csv`)
- `preprocessed_csv_path` - output path for the preprocessed CSV (default: `data/preprocessed.csv`)
- `sample_size` - number of benign samples and number of malicious samples to include, distributed evenly across attack types (default: `200`)

---

### Step 3: Augment the Dataset

Run the augmentation tool to generate the three-partition dataset used for evaluation.

```
python -m augmentation.augment <preprocessed_csv_path> <augmented_dataset_directory>
```

- `preprocessed_csv_path` - path to the preprocessed CSV from Step 2 (default: `data/preprocessed.csv`)
- `augmented_dataset_directory` - directory to store the three output CSV files (default: `data/augmented`)

Output files in `augmented_dataset_directory`:
- `A_benign.csv` - benign HTTP requests
- `B_malicious_clean.csv` - malicious HTTP requests without prompt injections
- `C_malicious_injected.csv` - malicious HTTP requests with prompt injection payloads