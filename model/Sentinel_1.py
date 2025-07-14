 

import torch
import torch.nn as nn
import numpy as np
import json
from pathlib import Path
from torch_geometric.data import Data
import random
import warnings
warnings.filterwarnings('ignore')

 

class SmartContractDataset(torch.utils.data.Dataset):
    def __init__(self, base_path, batch_names=['batch1'], balanced=False, random_seed=42):
        """
        Dataset loader برای قراردادهای هوشمند

        Args:
            base_path: مسیر پایه دیتاست
            batch_names: لیست نام batch ها
            balanced: آیا دیتاست متوازن شود
            random_seed: seed برای تکرارپذیری
        """
        self.base_path = Path(base_path)
        self.batch_names = batch_names if isinstance(batch_names, list) else [batch_names]
        self.balanced = balanced

        # خواندن همه batch ها
        all_entries = []
        total_safe = 0
        total_vuln = 0
        missing_files = 0

        for batch_name in self.batch_names:
            # مسیر صحیح: هر batch در پوشه خودش
            batch_path = self.base_path / batch_name
            index_file = batch_path / "ml_dataset" / f"dataset_index_{batch_name}.json"

            if not index_file.exists():
                print(f"  {index_file} یافت نشد!")
                continue

            with open(index_file, 'r') as f:
                batch_data = json.load(f)

            # بررسی وجود فایل‌ها قبل از اضافه کردن
            valid_entries = []
            batch_missing = 0

            for entry in batch_data['entries']:
                contract_id = entry['contract_id']

                # مسیرهای فایل‌های مورد نیاز
                graph_path = batch_path / "ml_dataset" / "graphs" / f"{contract_id}.npz"
                path_path = batch_path / "ml_dataset" / "paths" / f"{contract_id}.npz"

                # بررسی وجود هر دو فایل
                if graph_path.exists() and path_path.exists():
                    entry['batch_name'] = batch_name
                    valid_entries.append(entry)
                else:
                    batch_missing += 1
                    if batch_missing <= 5:  # فقط 5 مورد اول را نمایش بده
                        if not graph_path.exists():
                            print(f"    Missing graph file: {graph_path.name}")
                        if not path_path.exists():
                            print(f"    Missing path file: {path_path.name}")

            if batch_missing > 5:
                print(f"   ... and {batch_missing - 5} more missing files in {batch_name}")

            # اضافه کردن entries معتبر
            all_entries.extend(valid_entries)

            # شمارش
            batch_safe = len([e for e in valid_entries if e['label'] == 0])
            batch_vuln = len([e for e in valid_entries if e['label'] == 1])
            total_safe += batch_safe
            total_vuln += batch_vuln
            missing_files += batch_missing

            print(f"  {batch_name}: Safe={batch_safe}, Vulnerable={batch_vuln}, Missing={batch_missing}")

        # جداسازی safe و vulnerable
        self.safe_entries = [e for e in all_entries if e['label'] == 0]
        self.vulnerable_entries = [e for e in all_entries if e['label'] == 1]

        print(f"\n📊 مجموع Dataset:")
        print(f"   Safe contracts: {total_safe}")
        print(f"   Vulnerable contracts: {total_vuln}")
        if missing_files > 0:
            print(f"    Total missing files: {missing_files}")

        # بررسی اینکه آیا داده کافی داریم
        if len(all_entries) == 0:
            raise ValueError("No valid entries found! Please check your data files.")

        if balanced and len(self.safe_entries) == 0:
            raise ValueError("No safe contracts found for balanced dataset!")

        if balanced and len(self.vulnerable_entries) == 0:
            raise ValueError("No vulnerable contracts found for balanced dataset!")

        # متوازن‌سازی در صورت نیاز
        if balanced and len(self.safe_entries) > 0 and len(self.vulnerable_entries) > 0:
            random.seed(random_seed)
            min_size = min(len(self.safe_entries), len(self.vulnerable_entries))
            self.safe_entries = random.sample(self.safe_entries, min_size)
            self.entries = self.safe_entries + self.vulnerable_entries
            print(f"    Balanced to: {min_size} samples each")
        else:
            self.entries = all_entries

        # Shuffle
        random.seed(random_seed)
        random.shuffle(self.entries)

        print(f"\n Total valid samples in dataset: {len(self.entries)}")

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, idx):
        entry = self.entries[idx]
        contract_id = entry['contract_id']
        batch_name = entry['batch_name']

        # مسیر صحیح برای هر batch
        batch_path = self.base_path / batch_name

        # بارگذاری داده‌های گراف
        graph_path = batch_path / "ml_dataset" / "graphs" / f"{contract_id}.npz"
        try:
            graph_data = np.load(graph_path)
        except Exception as e:
            print(f"\n Error loading graph file: {graph_path}")
            print(f"   Error: {str(e)}")
            raise

        # بارگذاری داده‌های مسیر
        path_path = batch_path / "ml_dataset" / "paths" / f"{contract_id}.npz"
        try:
            path_data = np.load(path_path)
        except Exception as e:
            print(f"\n Error loading path file: {path_path}")
            print(f"   Error: {str(e)}")
            raise

        # ایجاد PyTorch Geometric Data object
        edge_index = torch.tensor(graph_data['edge_index'], dtype=torch.long)

        # ترکیب node features
        node_features = torch.tensor(graph_data['node_features'], dtype=torch.float)

        # اضافه کردن node types به عنوان one-hot
        num_nodes = int(graph_data['num_nodes'])
        node_types = graph_data['node_types']
        max_node_type = 10
        node_type_onehot = torch.zeros(num_nodes, max_node_type)

        # اطمینان از اینکه node_types در محدوده مجاز است
        valid_types = node_types < max_node_type
        node_type_onehot[valid_types, node_types[valid_types]] = 1

        # ترکیب همه node features
        x = torch.cat([node_features, node_type_onehot], dim=1)

        # ساخت graph data
        graph = Data(
            x=x,
            edge_index=edge_index,
            num_nodes=num_nodes
        )

        # Path data - بدون محدودیت تعداد مسیر
        max_seq_len = 20  # حداکثر طول هر مسیر (این را نگه می‌داریم برای پردازش sequence)

        path_sequences = path_data['path_sequences']
        path_lengths = path_data['path_lengths']
        path_features = path_data['path_features']
        risk_levels = path_data['risk_levels']
        num_paths = int(path_data['num_paths'])

        # فقط padding برای طول sequence ها (نه تعداد مسیرها)
        if num_paths > 0:
            current_seq_len = path_sequences.shape[1]
            if current_seq_len < max_seq_len:
                # اضافه کردن padding به طول sequences
                pad_width = ((0, 0), (0, max_seq_len - current_seq_len))
                path_sequences = np.pad(path_sequences, pad_width, mode='constant', constant_values=0)
            elif current_seq_len > max_seq_len:
                # برش اگر خیلی طولانی بود
                path_sequences = path_sequences[:, :max_seq_len]
                # طول‌ها را هم به‌روزرسانی می‌کنیم
                path_lengths = np.minimum(path_lengths, max_seq_len)
        else:
            # اگر اصلاً مسیری نداریم، یک مسیر خالی می‌سازیم
            path_sequences = np.zeros((1, max_seq_len))
            path_lengths = np.zeros(1)
            path_features = np.zeros((1, 6))
            risk_levels = np.zeros(1)
            num_paths = 0  # این مهم است که 0 بماند

        paths = {
            'sequences': torch.tensor(path_sequences, dtype=torch.long),
            'lengths': torch.tensor(path_lengths, dtype=torch.long),
            'features': torch.tensor(path_features, dtype=torch.float),
            'risk_levels': torch.tensor(risk_levels, dtype=torch.long),
            'num_paths': num_paths
        }

        # Label
        label = torch.tensor(entry['label'], dtype=torch.long)

        return {
            'graph': graph,
            'paths': paths,
            'label': label,
            'contract_id': contract_id,
            'has_paths': entry['num_paths'] > 0
        }

 

def test_dataset():
    """تست بارگذاری dataset با بررسی فایل‌های گمشده"""
    print("  Testing Dataset Loader (Fixed Version)...")
    print("="*60)

    # تنظیمات
    base_path = r"C:\Users\Hadis\Documents\NewModel1"

    # تست با batch1
    print("\n1️ Testing with batch1 only:")
    dataset = SmartContractDataset(
        base_path=base_path,
        batch_names=['batch1'],
        balanced=False
    )

    # نمایش چند نمونه
    print(f"\n نمایش 3 نمونه اول:")
    for i in range(min(3, len(dataset))):
        try:
            sample = dataset[i]
            print(f"\n   Sample {i+1}:")
            print(f"   - Contract ID: {sample['contract_id']}")
            print(f"   - Label: {'Vulnerable' if sample['label'] == 1 else 'Safe'}")
            print(f"   - Graph nodes: {sample['graph'].x.shape[0]}")
            print(f"   - Graph edges: {sample['graph'].edge_index.shape[1]}")
            print(f"   - Has paths: {sample['has_paths']}")
            print(f"   - Number of paths: {sample['paths']['num_paths']}")
            print(f"   - Path sequences shape: {sample['paths']['sequences'].shape}")
        except Exception as e:
            print(f"    Error loading sample {i+1}: {str(e)}")

    # تست balanced dataset
    print("\n\n  Testing balanced dataset:")
    try:
        dataset_balanced = SmartContractDataset(
            base_path=base_path,
            batch_names=['batch1'],
            balanced=True
        )

        # شمارش labels
        labels = [dataset_balanced[i]['label'].item() for i in range(len(dataset_balanced))]
        safe_count = labels.count(0)
        vuln_count = labels.count(1)
        print(f"\n   Balanced dataset: Safe={safe_count}, Vulnerable={vuln_count}")
    except Exception as e:
        print(f"    Error creating balanced dataset: {str(e)}")

    # تست batch1 و batch2
    print("\n\n Testing with both batches:")
    try:
        dataset_full = SmartContractDataset(
            base_path=base_path,
            batch_names=['batch1', 'batch2'],
            balanced=False
        )
        print("   Both batches loaded successfully!")

        # بررسی تعداد فایل‌های گمشده
        print(f"\n   Total valid entries: {len(dataset_full)}")

    except Exception as e:
        print(f"    Error loading batches: {str(e)}")

    print("\n Dataset loader test completed!")


if __name__ == "__main__":
    test_dataset()
