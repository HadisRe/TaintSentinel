# TaintSentinel: Path-Level Randomness Vulnerability Detection for Smart Contracts

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![GitHub Stars](https://img.shields.io/github/stars/HadisRe/TaintSentinel?style=social)](https://github.com/HadisRe/TaintSentinel/stargazers)

## Overview

TaintSentinel is a novel dual-stream Graph Neural Network (GNN) approach designed to detect bad randomness vulnerabilities in Ethereum smart contracts. By combining global contract analysis with path-specific taint tracking, TaintSentinel achieves state-of-the-art performance in identifying weak entropy sources that can be exploited by malicious actors.

### Key Features

- **Dual-Stream Architecture**: Combines global contract context with path-level analysis
- **Gated Fusion Mechanism**: Adaptive integration of global and local features  
- **Path Risk Assessment (PRA)**: Fine-grained risk classification for taint propagation paths
- **High Accuracy**: 87.5% F1-Score on balanced datasets
- **Practical Impact**: Successfully identified vulnerabilities in real-world contracts

## Performance

| Metric | Balanced Dataset | Imbalanced Dataset |
|--------|-----------------|-------------------|
| F1-Score | 0.875 | 0.611 |
| Precision | 0.921 | 0.537 |
| Recall | 0.833 | 0.707 |
| AUC-ROC | 0.951 | 0.940 |
| PRA | 0.970 | 0.920 |

## Quick Start

### Prerequisites

- Python 3.8+
- PyTorch 1.12+
- PyTorch Geometric
- NetworkX
- NumPy, Pandas, Scikit-learn

### Installation
```bash
# Clone the repository
git clone https://github.com/HadisRe/TaintSentinel.git
cd TaintSentinel

# Install dependencies
pip install -r requirements.txt

Dataset
The TaintSentinel dataset contains 2,017 smart contracts (148 vulnerable, 1,869 safe). Dataset is included in the repository under dataset/contracts/.
Running the Preprocessing Pipeline
Execute the preprocessing steps in order:

cd preprocessing
python complete_parser1.py
python source2.py
python sink3.py
python ModularSemanticGraph.py
python TaintAnalysis.py

Training the Model
cd ../model
python Sentinel_3.py

Repository Structure
TaintSentinel/
├── dataset/
│   ├── contracts/
│   │   ├── vulnerable/
│   │   └── safe/
│   └── dataset_metadata.json
├── preprocessing/
│   ├── complete_parser1.py
│   ├── source2.py
│   ├── sink3.py
│   ├── ModularSemanticGraph.py
│   └── TaintAnalysis.py
├── model/
│   ├── Sentinel_1.py
│   ├── Sentinel_2.py
│   ├── Sentinel_3.py
│   └── Sentinel_4.py
├── requirements.txt
└── README.md

Technical Details
Preprocessing Pipeline

AST Extraction: Parses Solidity code into Abstract Syntax Trees
Source Detection: Identifies weak entropy sources (block.timestamp, blockhash)
Sink Detection: Locates critical operations (gambling payouts)
Graph Construction: Builds control-flow and data-flow graphs
Taint Analysis: Traces paths from sources to sinks with risk scoring

Model Architecture

GlobalGNN: Processes entire contract structure using Graph Convolutional Networks
PathGNN: Analyzes individual taint paths with LSTM and attention mechanisms
Gated Fusion: Adaptively combines global and path-level features
Risk Classifier: Predicts vulnerability likelihood and path risk levels

Results
Our experiments demonstrate TaintSentinel's effectiveness:

Balanced Dataset: Achieves 87.5% F1-Score with high precision (92.1%)
Imbalanced Dataset: Maintains 70.7% recall in real-world scenarios
Path Risk Accuracy: 97% accuracy in classifying path risk levels

Contributing
We welcome contributions! Please feel free to submit issues and pull requests.
License
This project is licensed under the MIT License - see the LICENSE file for details.
Citation
If you use TaintSentinel in your research, please cite:

@inproceedings{taintsentinel2024,
  title={TaintSentinel: Path-Level Neural Architecture for Smart Contract Randomness Vulnerability Detection},
  author={[Your Name]},
  booktitle={[Conference Name]},
  year={2024}
}
