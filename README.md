# TaintSentinel: Path-Level Neural Architecture for Smart Contract Randomness Vulnerability Detection

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![GitHub Stars](https://img.shields.io/github/stars/HadisRe/TaintSentinel?style=social)](https://github.com/HadisRe/TaintSentinel/stargazers)

## 🎯 Overview

TaintSentinel is a novel dual-stream Graph Neural Network (GNN) approach designed to detect bad randomness vulnerabilities in Ethereum smart contracts. By combining global contract analysis with path-specific taint tracking, TaintSentinel achieves state-of-the-art performance in identifying weak entropy sources that can be exploited by malicious actors.

### Key Features
- **Dual-Stream Architecture**: Combines global contract context with path-level analysis
- **Gated Fusion Mechanism**: Adaptive integration of global and local features
- **Path Risk Assessment (PRA)**: Fine-grained risk classification for taint propagation paths
- **High Accuracy**: 87.5% F1-Score on balanced datasets
- **Practical Impact**: Successfully identified vulnerabilities in real-world contracts
