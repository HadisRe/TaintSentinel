import os
import json
import shutil
from pathlib import Path
from datetime import datetime

def add_batch2_to_dataset():
    """
    اضافه کردن batch2 به دیتاست موجود
    """
    
    # مسیرهای batch2
    batch2_paths = {
        "vulnerable": r"C:\Users\Hadis\Documents\NewModel1\batch2\vulnerable1",
        "safe": r"C:\Users\Hadis\Documents\NewModel1\batch2\safe1"
    }
    
    # مسیر دیتاست موجود
    dataset_dir = Path("TaintSentinel-Dataset")
    
    if not dataset_dir.exists():
        print("❌ Error: TaintSentinel-Dataset folder not found!")
        print("Please run the main organization script first.")
        return
    
    # بارگذاری متادیتای موجود
    metadata_file = dataset_dir / "dataset_metadata.json"
    with open(metadata_file, 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    
    # شمارش فایل‌های موجود برای ادامه ID
    existing_contracts = len(metadata["contracts"])
    contract_id = existing_contracts
    
    # شمارنده‌ها برای batch2
    batch2_vuln_count = 0
    batch2_safe_count = 0
    
    # پردازش قراردادهای آسیب‌پذیر batch2
    print("Processing batch2 vulnerable contracts...")
    vuln_path = Path(batch2_paths["vulnerable"])
    vulnerable_dir = dataset_dir / "contracts" / "vulnerable"
    
    if vuln_path.exists():
        vuln_files = list(vuln_path.glob("*.sol"))
        
        for sol_file in vuln_files:
            # بررسی که آیا فایل قبلاً اضافه نشده
            if not (vulnerable_dir / sol_file.name).exists():
                # کپی فایل
                dest_file = vulnerable_dir / sol_file.name
                shutil.copy2(sol_file, dest_file)
                
                # اضافه کردن به متادیتا
                contract_info = {
                    "id": f"vuln_{contract_id:04d}",
                    "address": sol_file.stem,
                    "filename": sol_file.name,
                    "label": "vulnerable",
                    "vulnerability_type": "bad_randomness",
                    "batch": "batch2",  # اضافه کردن اطلاعات batch
                    "path": f"contracts/vulnerable/{sol_file.name}"
                }
                
                metadata["contracts"].append(contract_info)
                batch2_vuln_count += 1
                contract_id += 1
            else:
                print(f"  ⚠️  Skipping duplicate: {sol_file.name}")
        
        print(f"  ✓ Added {batch2_vuln_count} new vulnerable contracts from batch2")
    else:
        print(f"  ❌ Path not found: {batch2_paths['vulnerable']}")
    
    # پردازش قراردادهای ایمن batch2
    print("\nProcessing batch2 safe contracts...")
    safe_path = Path(batch2_paths["safe"])
    safe_dir = dataset_dir / "contracts" / "safe"
    
    if safe_path.exists():
        safe_files = list(safe_path.glob("*.sol"))
        
        for sol_file in safe_files:
            # بررسی که آیا فایل قبلاً اضافه نشده
            if not (safe_dir / sol_file.name).exists():
                # کپی فایل
                dest_file = safe_dir / sol_file.name
                shutil.copy2(sol_file, dest_file)
                
                # اضافه کردن به متادیتا
                contract_info = {
                    "id": f"safe_{contract_id:04d}",
                    "address": sol_file.stem,
                    "filename": sol_file.name,
                    "label": "safe",
                    "vulnerability_type": "none",
                    "batch": "batch2",
                    "path": f"contracts/safe/{sol_file.name}"
                }
                
                metadata["contracts"].append(contract_info)
                batch2_safe_count += 1
                contract_id += 1
            else:
                print(f"  ⚠️  Skipping duplicate: {sol_file.name}")
        
        print(f"  ✓ Added {batch2_safe_count} new safe contracts from batch2")
    else:
        print(f"  ❌ Path not found: {batch2_paths['safe']}")
    
    # آپدیت آمار
    metadata["statistics"]["vulnerable_contracts"] += batch2_vuln_count
    metadata["statistics"]["safe_contracts"] += batch2_safe_count
    metadata["statistics"]["total_contracts"] = metadata["statistics"]["vulnerable_contracts"] + metadata["statistics"]["safe_contracts"]
    
    # اضافه کردن آمار batch ها
    if "batch_statistics" not in metadata:
        metadata["batch_statistics"] = {
            "batch1": {
                "vulnerable": metadata["statistics"]["vulnerable_contracts"] - batch2_vuln_count,
                "safe": metadata["statistics"]["safe_contracts"] - batch2_safe_count
            }
        }
    
    metadata["batch_statistics"]["batch2"] = {
        "vulnerable": batch2_vuln_count,
        "safe": batch2_safe_count,
        "total": batch2_vuln_count + batch2_safe_count
    }
    
    # آپدیت dataset splits
    total = len(metadata["contracts"])
    train_size = int(0.7 * total)
    val_size = int(0.15 * total)
    
    metadata["dataset_splits"] = {
        "train": {
            "start": 0,
            "end": train_size,
            "size": train_size
        },
        "validation": {
            "start": train_size,
            "end": train_size + val_size,
            "size": val_size
        },
        "test": {
            "start": train_size + val_size,
            "end": total,
            "size": total - train_size - val_size
        }
    }
    
    # آپدیت تاریخ
    metadata["dataset_info"]["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    metadata["dataset_info"]["version"] = "1.1"  # افزایش نسخه
    
    # ذخیره متادیتای آپدیت شده
    with open(metadata_file, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    # آپدیت contracts_list.json
    contracts_simple = {
        "vulnerable": [c["address"] for c in metadata["contracts"] if c["label"] == "vulnerable"],
        "safe": [c["address"] for c in metadata["contracts"] if c["label"] == "safe"]
    }
    
    with open(dataset_dir / "contracts_list.json", "w", encoding="utf-8") as f:
        json.dump(contracts_simple, f, indent=2)
    
    # آپدیت README
    update_readme(dataset_dir, metadata)
    
    print(f"\n=== Batch2 Addition Complete ===")
    print(f"New statistics:")
    print(f"  Total contracts: {metadata['statistics']['total_contracts']:,}")
    print(f"  - Vulnerable: {metadata['statistics']['vulnerable_contracts']}")
    print(f"  - Safe: {metadata['statistics']['safe_contracts']:,}")
    print(f"\nBatch breakdown:")
    if "batch_statistics" in metadata:
        for batch, stats in metadata["batch_statistics"].items():
            print(f"  {batch}: {stats.get('total', stats.get('vulnerable', 0) + stats.get('safe', 0))} contracts")

def update_readme(dataset_dir, metadata):
    """آپدیت فایل README با آمار جدید"""
    readme_content = f"""# TaintSentinel Bad Randomness Dataset

## Overview
This dataset contains Ethereum smart contracts for detecting bad randomness vulnerabilities using the TaintSentinel approach.

### Dataset Statistics
- **Total Contracts**: {metadata['statistics']['total_contracts']:,}
- **Vulnerable Contracts**: {metadata['statistics']['vulnerable_contracts']}
- **Safe Contracts**: {metadata['statistics']['safe_contracts']:,}
- **Vulnerability Type**: Bad Randomness (weak entropy sources)

### Batch Distribution
"""
    
    if "batch_statistics" in metadata:
        for batch, stats in metadata["batch_statistics"].items():
            total = stats.get('total', stats.get('vulnerable', 0) + stats.get('safe', 0))
            readme_content += f"- **{batch.capitalize()}**: {total} contracts ({stats.get('vulnerable', 0)} vulnerable, {stats.get('safe', 0)} safe)\n"
    
    readme_content += f"""
### Dataset Splits
- **Training Set**: {metadata['dataset_splits']['train']['size']:,} contracts (70%)
- **Validation Set**: {metadata['dataset_splits']['validation']['size']:,} contracts (15%)
- **Test Set**: {metadata['dataset_splits']['test']['size']:,} contracts (15%)

## Dataset Structure
```
TaintSentinel-Dataset/
├── contracts/
│   ├── vulnerable/         # {metadata['statistics']['vulnerable_contracts']} contracts with bad randomness
│   └── safe/              # {metadata['statistics']['safe_contracts']:,} contracts without vulnerabilities
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
@article{{taintsentinel2024,
  title={{TaintSentinel: A Novel Dual-Stream GNN Approach with Gated Fusion and Path Risk Assessment for Smart Contract Bad Randomness Detection}},
  author={{[Authors]}},
  journal={{[Journal/Conference]}},
  year={{2024}}
}}
```

## License
This dataset is released under the MIT License.
"""
    
    with open(dataset_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)

# اجرای اسکریپت
if __name__ == "__main__":
    add_batch2_to_dataset()