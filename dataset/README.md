# TaintSentinel Bad Randomness Dataset

## Overview
This dataset contains Ethereum smart contracts for detecting bad randomness vulnerabilities using the TaintSentinel approach.

### Dataset Statistics
- **Total Contracts**: 4,467
- **Vulnerable Contracts**: 231
- **Safe Contracts**: 4,236
- **Vulnerability Type**: Bad Randomness (weak entropy sources)

### Batch Distribution
- **Batch1**: 2017 contracts (148 vulnerable, 1869 safe)
- **Batch2**: 2450 contracts (83 vulnerable, 2367 safe)

### Dataset Splits
- **Training Set**: 3,126 contracts (70%)
- **Validation Set**: 670 contracts (15%)
- **Test Set**: 671 contracts (15%)

## Dataset Structure
```
TaintSentinel-Dataset/
├── contracts/
│   ├── vulnerable/         # 231 contracts with bad randomness
│   └── safe/              # 4,236 contracts without vulnerabilities
├── dataset_metadata.json   # Complete metadata with all contract information
├── contracts_list.json     # Simple list of contract addresses
└── README.md              # This file
```

## Version History
- v1.1: Added batch2 contracts
- v1.0: Initial release with batch1 contracts

## File Format
All contracts are in Solidity format (.sol files) and are named by their Ethereum address.

## Usage

### Loading the Dataset
```python
import json
from pathlib import Path

# Load metadata
with open('dataset_metadata.json', 'r') as f:
    metadata = json.load(f)

# Filter by batch if needed
batch1_contracts = [c for c in metadata['contracts'] if c.get('batch') == 'batch1']
batch2_contracts = [c for c in metadata['contracts'] if c.get('batch') == 'batch2']
```

### Using with TaintSentinel
1. Run preprocessing scripts to generate CFG and taint paths
2. Use the generated graphs with the dual-stream GNN model
3. Evaluate using the provided train/validation/test splits

## Citation
If you use this dataset in your research, please cite:
```bibtex
@article{taintsentinel2024,
  title={TaintSentinel: A Novel Dual-Stream GNN Approach with Gated Fusion and Path Risk Assessment for Smart Contract Bad Randomness Detection},
  author={[Authors]},
  journal={[Journal/Conference]},
  year={2024}
}
```

## License
This dataset is released under the MIT License.
