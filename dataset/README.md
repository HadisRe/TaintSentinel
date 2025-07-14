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
│   ├── vulnerable/         
│   └── safe/               
├── dataset_metadata.json   
├── contracts_list.json      
└── README.md              
```
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

