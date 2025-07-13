"""
TaintSentinel - Part 2: GNN Models
این قسمت شامل GlobalGNN و PathGNN با Hierarchical Aggregation است
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
import numpy as np
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

# Import dataset from previous part
from Sentinel_1 import SmartContractDataset

# ===========================
# GlobalGNN Model
# ===========================

class GlobalGNN(nn.Module):
    """شبکه عصبی برای پردازش کل گراف"""

    def __init__(self, input_dim, hidden_dim, num_layers=3, dropout=0.2):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns = nn.ModuleList()

        # First layer
        self.convs.append(GCNConv(input_dim, hidden_dim))
        self.bns.append(nn.BatchNorm1d(hidden_dim))

        # Hidden layers
        for _ in range(num_layers - 1):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))
            self.bns.append(nn.BatchNorm1d(hidden_dim))

        self.dropout = dropout
        self.hidden_dim = hidden_dim

    def forward(self, x, edge_index, batch):
        # Node-level processing
        for i, (conv, bn) in enumerate(zip(self.convs, self.bns)):
            x = conv(x, edge_index)
            x = bn(x)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

        # Graph-level pooling - ترکیب mean و max pooling
        graph_embedding = torch.cat([
            global_mean_pool(x, batch),
            global_max_pool(x, batch)
        ], dim=1)

        return graph_embedding

# ===========================
# PathGNN Model with Hierarchical Aggregation
# ===========================

class PathGNN(nn.Module):
    """شبکه عصبی برای پردازش مسیرها با قابلیت aggregation"""

    def __init__(self, node_embedding_dim, path_feature_dim, hidden_dim, dropout=0.2):
        super().__init__()

        # برای embedding گره‌های مسیر
        self.node_projection = nn.Linear(node_embedding_dim, hidden_dim)

        # LSTM برای پردازش sequence
        self.lstm = nn.LSTM(
            input_size=hidden_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if dropout > 0 else 0
        )

        # برای ترکیب با path features
        self.feature_projection = nn.Linear(path_feature_dim, hidden_dim)
        self.path_fusion = nn.Linear(hidden_dim * 2 + hidden_dim, hidden_dim)

        # Hierarchical Aggregation layers
        self.attention_projection = nn.Linear(hidden_dim, 1)
        self.aggregation_mlp = nn.Sequential(
            nn.Linear(hidden_dim * 3, hidden_dim * 2),  # mean, max, weighted
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim)
        )

        self.dropout = dropout
        self.hidden_dim = hidden_dim

    def forward(self, path_data, node_embeddings):
        """
        Args:
            path_data: dict containing sequences, lengths, features, num_paths
            node_embeddings: node features from the graph
        Returns:
            aggregated_embedding: fixed-size representation of all paths
        """

        if path_data['num_paths'] == 0:
            # اگر مسیری نداریم، embedding صفر برمی‌گردانیم
            return torch.zeros(1, self.hidden_dim).to(node_embeddings.device)

        # استخراج داده‌ها
        sequences = path_data['sequences']  # [num_paths, max_seq_len]
        lengths = path_data['lengths']      # [num_paths]
        features = path_data['features']    # [num_paths, 6]
        num_paths = path_data['num_paths']

        # پردازش هر مسیر
        path_embeddings = []

        for i in range(num_paths):
            seq_len = int(lengths[i])
            if seq_len > 0:
                # گرفتن embedding گره‌های این مسیر
                node_indices = sequences[i, :seq_len].long()  # اطمینان از integer بودن
                path_nodes = node_embeddings[node_indices]
                path_nodes = self.node_projection(path_nodes)

                # LSTM processing
                lstm_out, (h_n, _) = self.lstm(path_nodes.unsqueeze(0))

                # Debug shapes
                # print(f"Debug - h_n shape: {h_n.shape}")

                # آخرین hidden state (bidirectional)
                # h_n shape: [num_layers*2, 1, hidden_dim]
                h_forward = h_n[-2].unsqueeze(0)   # [1, 1, hidden_dim]
                h_backward = h_n[-1].unsqueeze(0)  # [1, 1, hidden_dim]
                path_lstm = torch.cat([h_forward, h_backward], dim=2).squeeze(0)  # [1, hidden_dim*2]

                # ترکیب با path features
                path_feat = self.feature_projection(features[i].unsqueeze(0))  # [1, hidden_dim]

                # Fusion
                combined = torch.cat([path_lstm, path_feat], dim=1)  # [1, hidden_dim*2 + hidden_dim]
                path_embedding = self.path_fusion(combined)
                path_embedding = F.relu(path_embedding)
                path_embedding = path_embedding.squeeze(0)  # [hidden_dim]

                path_embeddings.append(path_embedding)

        # Stack all path embeddings
        if path_embeddings:  # اطمینان از اینکه لیست خالی نیست
            path_embeddings = torch.stack(path_embeddings)  # [num_paths, hidden_dim]
        else:
            # اگر هیچ path معتبری نداشتیم
            return torch.zeros(1, self.hidden_dim).to(node_embeddings.device)

        # Hierarchical Aggregation
        # 1. Attention-weighted aggregation
        attention_scores = self.attention_projection(path_embeddings)  # [num_paths, 1]
        attention_weights = F.softmax(attention_scores, dim=0)
        weighted_paths = (path_embeddings * attention_weights).sum(dim=0, keepdim=True)  # [1, hidden_dim]

        # 2. Mean pooling
        mean_paths = path_embeddings.mean(dim=0, keepdim=True)  # [1, hidden_dim]

        # 3. Max pooling
        max_paths, _ = path_embeddings.max(dim=0, keepdim=True)  # [1, hidden_dim]

        # 4. Final aggregation
        aggregated = torch.cat([weighted_paths, mean_paths, max_paths], dim=1)  # [1, hidden_dim*3]
        aggregated_embedding = self.aggregation_mlp(aggregated)
        aggregated_embedding = F.dropout(aggregated_embedding, p=self.dropout, training=self.training)

        return aggregated_embedding

# ===========================
# Custom Collate Function
# ===========================

def custom_collate_fn(batch):
    """
    Custom collate function برای batch processing با تعداد متغیر مسیر
    """
    # جمع‌آوری graphs
    graphs = [item['graph'] for item in batch]
    batched_graph = Batch.from_data_list(graphs)

    # جمع‌آوری paths و سایر داده‌ها
    paths = [item['paths'] for item in batch]
    labels = torch.stack([item['label'] for item in batch])
    contract_ids = [item['contract_id'] for item in batch]
    has_paths = torch.tensor([item['has_paths'] for item in batch])

    return {
        'graph': batched_graph,
        'paths': paths,  # لیست از dict ها - هر کدام با تعداد مسیر متفاوت
        'labels': labels,
        'contract_ids': contract_ids,
        'has_paths': has_paths
    }

# ===========================
# Test Script
# ===========================

def test_models():
    """تست GlobalGNN و PathGNN"""
    print("🧪 Testing GNN Models...")
    print("="*60)

    # تنظیمات
    base_path = r"C:\Users\Hadis\Documents\NewModel1"
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🖥️ Using device: {device}")

    # بارگذاری dataset
    dataset = SmartContractDataset(
        base_path=base_path,
        batch_names=['batch1'],
        balanced=False
    )

    # گرفتن یک batch کوچک برای تست
    from torch.utils.data import DataLoader
    test_loader = DataLoader(
        dataset,
        batch_size=4,
        shuffle=False,
        collate_fn=custom_collate_fn
    )

    # گرفتن اولین batch
    batch = next(iter(test_loader))

    print(f"\n📊 Batch info:")
    print(f"   - Batch size: {len(batch['labels'])}")
    print(f"   - Graph nodes: {batch['graph'].x.shape}")
    print(f"   - Number of paths per contract: {[p['num_paths'] for p in batch['paths']]}")

    # تست GlobalGNN
    print("\n1️⃣ Testing GlobalGNN:")
    node_feature_dim = batch['graph'].x.shape[1]
    global_gnn = GlobalGNN(
        input_dim=node_feature_dim,
        hidden_dim=128,
        num_layers=3
    ).to(device)

    # Forward pass
    batch['graph'] = batch['graph'].to(device)
    global_output = global_gnn(
        batch['graph'].x,
        batch['graph'].edge_index,
        batch['graph'].batch
    )
    print(f"   ✅ Global GNN output shape: {global_output.shape}")
    print(f"      Expected: [batch_size, hidden_dim*2] = [4, 256]")

    # تست PathGNN
    print("\n2️⃣ Testing PathGNN:")
    path_gnn = PathGNN(
        node_embedding_dim=node_feature_dim,
        path_feature_dim=6,
        hidden_dim=64
    ).to(device)

    # تست برای هر قرارداد در batch
    path_outputs = []
    for i in range(len(batch['labels'])):
        # گرفتن node embeddings این گراف
        graph_mask = (batch['graph'].batch == i)
        graph_nodes = batch['graph'].x[graph_mask]

        # پردازش paths
        path_data = batch['paths'][i]
        # انتقال به device
        for key in ['sequences', 'lengths', 'features']:
            if key in path_data:
                path_data[key] = path_data[key].to(device)

        print(f"\n   Processing contract {i+1}:")
        print(f"      - Graph nodes shape: {graph_nodes.shape}")
        print(f"      - Number of paths: {path_data['num_paths']}")

        path_output = path_gnn(path_data, graph_nodes)
        path_outputs.append(path_output)

        print(f"      - Output shape: {path_output.shape}")

    # Stack outputs
    path_outputs = torch.cat(path_outputs, dim=0)
    print(f"\n   ✅ Final path embeddings shape: {path_outputs.shape}")
    print(f"      Expected: [batch_size, hidden_dim] = [4, 64]")

    # تست حالت خاص: قرارداد بدون مسیر
    print("\n3️⃣ Testing edge case (no paths):")
    # استفاده از آخرین graph_nodes از loop قبلی
    empty_path_data = {
        'sequences': torch.zeros(1, 20).long().to(device),
        'lengths': torch.zeros(1).long().to(device),
        'features': torch.zeros(1, 6).float().to(device),
        'num_paths': 0
    }
    empty_output = path_gnn(empty_path_data, graph_nodes)
    print(f"   ✅ Empty path output shape: {empty_output.shape}")
    print(f"      All zeros: {torch.all(empty_output == 0).item()}")
    
    print("\n✅ Model tests completed successfully!")
    

if __name__ == "__main__":
    test_models()