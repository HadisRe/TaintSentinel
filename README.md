# TaintSentinel: Path-Level Randomness Vulnerability Detection for Smart Contracts

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![GitHub Stars](https://img.shields.io/github/stars/HadisRe/TaintSentinel?style=social)](https://github.com/HadisRe/TaintSentinel/stargazers)

##  Overview

TaintSentinel is a novel dual-stream Graph Neural Network (GNN) approach designed to detect bad randomness vulnerabilities in Ethereum smart contracts. By combining global contract analysis with path-specific taint tracking, TaintSentinel achieves state-of-the-art performance in identifying weak entropy sources that can be exploited by malicious actors.

### Key Features
- **Dual-Stream Architecture**: Combines global contract context with path-level analysis
- **Gated Fusion Mechanism**: Adaptive integration of global and local features
- **Path Risk Assessment (PRA)**: Fine-grained risk classification for taint propagation paths
- **High Accuracy**: 87.5% F1-Score on balanced datasets
- **Practical Impact**: Successfully identified vulnerabilities in real-world contracts
##  Performance

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
