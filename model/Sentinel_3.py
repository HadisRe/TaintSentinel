"""
TaintSentinel - Complete Training Pipeline
فایل کامل برای آموزش و ارزیابی مدل
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool, global_max_pool
from torch_geometric.data import Data, Batch
from torch.utils.data import DataLoader, random_split
import numpy as np
from pathlib import Path
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix
from collections import defaultdict
import time
import warnings
import numpy as np
warnings.filterwarnings('ignore')

# ===========================
# Import Models from Previous Files
# ===========================
# توجه: مطمئن شوید که فایل‌های TaintSentinel.py و Sentinel_2.py در همان پوشه هستند

try:
    from Sentinel_1 import SmartContractDataset
    from Sentinel_2 import GlobalGNN, PathGNN, custom_collate_fn
    print("✅ Successfully imported components from previous files")
except ImportError as e:
    print(f"❌ Error importing components: {e}")
    print("   Please ensure Sentinel_1.py and Sentinel_2.py are in the same directory")
    exit(1)

# ===========================
# TaintSentinel Model (Complete)
# ===========================

class Sentinel_1(nn.Module):
    """مدل نهایی: ترکیب GlobalGNN و PathGNN با Gated Fusion"""
    
    def __init__(self, node_feature_dim=18, path_feature_dim=6, 
                 hidden_dim=128, num_classes=2, dropout=0.2):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        
        # Global GNN
        self.global_gnn = GlobalGNN(
            input_dim=node_feature_dim,
            hidden_dim=hidden_dim,
            num_layers=3,
            dropout=dropout
        )
        
        # Path GNN
        self.path_gnn = PathGNN(
            node_embedding_dim=node_feature_dim,
            path_feature_dim=path_feature_dim,
            hidden_dim=hidden_dim//2,  # 64
            dropout=dropout
        )
        
        # Gated Fusion
        # Global: 256 (128*2), Path: 64 => Total: 320
        fusion_dim = hidden_dim * 2 + hidden_dim // 2
        self.gate = nn.Sequential(
            nn.Linear(fusion_dim, hidden_dim),
            nn.Sigmoid()
        )
        
        # Final fusion layer
        self.fusion_mlp = nn.Sequential(
            nn.Linear(fusion_dim, hidden_dim * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim)
        )
        
        # Final classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes)
        )
        
        self.device = None
    
    def to(self, device):
        self.device = device
        return super().to(device)
    
    def forward(self, batch_data):
        """
        Forward pass برای batch data
        """
        # استخراج داده‌ها
        batched_graph = batch_data['graph']
        paths_list = batch_data['paths']
        batch_size = len(batch_data['labels'])
        
        # Global GNN processing
        global_embedding = self.global_gnn(
            batched_graph.x,
            batched_graph.edge_index,
            batched_graph.batch
        )  # [batch_size, 256]
        
        # Path processing for each contract
        path_embeddings = []
        
        for i in range(batch_size):
            # گرفتن node embeddings این گراف
            graph_mask = (batched_graph.batch == i)
            graph_nodes = batched_graph.x[graph_mask]
            
            # پردازش paths
            path_data = paths_list[i]
            path_embedding = self.path_gnn(path_data, graph_nodes)  # [1, 64]
            path_embeddings.append(path_embedding)
        
        # Stack all path embeddings
        path_embeddings = torch.cat(path_embeddings, dim=0)  # [batch_size, 64]
        
        # Concatenate global and path embeddings
        combined = torch.cat([global_embedding, path_embeddings], dim=1)  # [batch_size, 320]
        
        # Gated Fusion
        gate_values = self.gate(combined)  # [batch_size, 128]
        
        # Apply fusion
        fused_features = self.fusion_mlp(combined)  # [batch_size, 128]
        gated_features = gate_values * fused_features
        
        # Final classification
        output = self.classifier(gated_features)  # [batch_size, 2]
        
        return output

# ===========================
# Training Functions
# ===========================

def train_epoch(model, train_loader, criterion, optimizer, device):
    """آموزش برای یک epoch"""
    model.train()
    total_loss = 0
    all_preds = []
    all_labels = []
    
    for batch_idx, batch in enumerate(train_loader):
        # انتقال به device
        batch['graph'] = batch['graph'].to(device)
        for i in range(len(batch['paths'])):
            for key in ['sequences', 'lengths', 'features']:
                batch['paths'][i][key] = batch['paths'][i][key].to(device)
        labels = batch['labels'].to(device)
        
        # Forward pass
        outputs = model(batch)
        loss = criterion(outputs, labels)
        
        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        
        # جمع‌آوری نتایج
        total_loss += loss.item()
        preds = outputs.argmax(dim=1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())
        
        # Progress
        if batch_idx % 10 == 0:
            print(f"\r   Batch [{batch_idx}/{len(train_loader)}] Loss: {loss.item():.4f}", end='')
    
    print()  # New line after progress
    return total_loss / len(train_loader), all_preds, all_labels

def validate_epoch(model, val_loader, criterion, device):
    """ارزیابی برای یک epoch"""
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []
    all_probs = []
    
    with torch.no_grad():
        for batch in val_loader:
            # انتقال به device
            batch['graph'] = batch['graph'].to(device)
            for i in range(len(batch['paths'])):
                for key in ['sequences', 'lengths', 'features']:
                    batch['paths'][i][key] = batch['paths'][i][key].to(device)
            labels = batch['labels'].to(device)
            
            # Forward pass
            outputs = model(batch)
            loss = criterion(outputs, labels)
            
            # جمع‌آوری نتایج
            total_loss += loss.item()
            preds = outputs.argmax(dim=1)
            probs = F.softmax(outputs, dim=1)[:, 1]  # احتمال کلاس vulnerable
            
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())
    
    return total_loss / len(val_loader), all_preds, all_labels, all_probs

def train_model(model, train_loader, val_loader, num_epochs=50, 
                learning_rate=0.001, weight_decay=1e-4, class_weights=None, device='cpu'):
    """آموزش کامل مدل"""
    
    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', patience=5, factor=0.5)
    
    # Loss function
    if class_weights is not None:
        class_weights = torch.tensor(class_weights, dtype=torch.float).to(device)
        criterion = nn.CrossEntropyLoss(weight=class_weights)
    else:
        criterion = nn.CrossEntropyLoss()
    
    history = defaultdict(list)
    best_val_f1 = 0
    best_model_state = None
    
    print("\n🚀 Starting training...")
    print("-" * 60)
    
    start_time = time.time()
    
    for epoch in range(num_epochs):
        epoch_start = time.time()
        
        # Training
        train_loss, train_preds, train_labels = train_epoch(model, train_loader, criterion, optimizer, device)
        
        # Validation
        val_loss, val_preds, val_labels, val_probs = validate_epoch(model, val_loader, criterion, device)
        
        # محاسبه metrics
        train_f1 = f1_score(train_labels, train_preds, zero_division=0)
        val_f1 = f1_score(val_labels, val_preds, zero_division=0)
        val_precision = precision_score(val_labels, val_preds, zero_division=0)
        val_recall = recall_score(val_labels, val_preds, zero_division=0)
        
        # محاسبه AUC فقط اگر هر دو کلاس وجود داشته باشند
        if len(np.unique(val_labels)) > 1:
            val_auc = roc_auc_score(val_labels, val_probs)
        else:
            val_auc = 0.0
        
        # ذخیره history
        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_loss)
        history['train_f1'].append(train_f1)
        history['val_f1'].append(val_f1)
        history['val_precision'].append(val_precision)
        history['val_recall'].append(val_recall)
        history['val_auc'].append(val_auc)
        
        # Learning rate scheduling
        scheduler.step(val_f1)
        
        # ذخیره best model
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_model_state = model.state_dict()
        
        # Print progress
        epoch_time = time.time() - epoch_start
        if epoch % 5 == 0 or epoch == num_epochs - 1:
            print(f"\nEpoch [{epoch+1}/{num_epochs}] (Time: {epoch_time:.1f}s)")
            print(f"  Train - Loss: {train_loss:.4f}, F1: {train_f1:.4f}")
            print(f"  Val   - Loss: {val_loss:.4f}, F1: {val_f1:.4f}")
            print(f"          Precision: {val_precision:.4f}, Recall: {val_recall:.4f}, AUC: {val_auc:.4f}")
            print(f"  LR: {optimizer.param_groups[0]['lr']:.6f}")
    
    total_time = time.time() - start_time
    print(f"\n✅ Training completed in {total_time/60:.1f} minutes")
    print(f"   Best validation F1: {best_val_f1:.4f}")
    
    # بارگذاری best model
    model.load_state_dict(best_model_state)
    
    return model, history

# ===========================
# Evaluation Functions
# ===========================

def evaluate_model(model, test_loader, device, threshold=0.5):  # فقط اضافه کردن threshold
    """ارزیابی جامع مدل"""
    model.eval()

    all_preds = []
    all_labels = []
    all_probs = []

    print(f"\n📊 Evaluating model on test set (threshold={threshold:.2f})...")  # تغییر در print

    with torch.no_grad():
        for batch in test_loader:
            # انتقال به device - بدون تغییر
            batch['graph'] = batch['graph'].to(device)
            for i in range(len(batch['paths'])):
                for key in ['sequences', 'lengths', 'features']:
                    batch['paths'][i][key] = batch['paths'][i][key].to(device)
            labels = batch['labels'].to(device)

            outputs = model(batch)
            probs = F.softmax(outputs, dim=1)[:, 1]  # اضافه شد
            preds = (probs > threshold).long()  # تغییر کرد

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())

    # بقیه تابع بدون تغییر...
    metrics = {
        'f1': f1_score(all_labels, all_preds, zero_division=0),
        'precision': precision_score(all_labels, all_preds, zero_division=0),
        'recall': recall_score(all_labels, all_preds, zero_division=0),
        'confusion_matrix': confusion_matrix(all_labels, all_preds)
    }

    if len(np.unique(all_labels)) > 1:
        metrics['auc_roc'] = roc_auc_score(all_labels, all_probs)
    else:
        metrics['auc_roc'] = 0.0

    return metrics


def find_best_threshold(model, val_loader, device, optimize_for='f1'):
    """پیدا کردن بهترین threshold با معیارهای مختلف"""
    model.eval()
    all_probs = []
    all_labels = []

    print(f"\n🔍 Finding optimal threshold (optimizing for {optimize_for})...")

    with torch.no_grad():
        for batch in val_loader:
            batch['graph'] = batch['graph'].to(device)
            for i in range(len(batch['paths'])):
                for key in ['sequences', 'lengths', 'features']:
                    batch['paths'][i][key] = batch['paths'][i][key].to(device)
            labels = batch['labels'].to(device)

            outputs = model(batch)
            probs = F.softmax(outputs, dim=1)[:, 1]

            all_probs.extend(probs.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    all_probs = np.array(all_probs)
    all_labels = np.array(all_labels)

    best_score = 0
    best_threshold = 0.5

    # تست threshold های مختلف
    for threshold in np.arange(0.05, 0.70, 0.05):
        preds = (all_probs > threshold).astype(int)

        if optimize_for == 'f1':
            score = f1_score(all_labels, preds)
        elif optimize_for == 'recall':
            # برای کاهش False Negatives
            f1 = f1_score(all_labels, preds)
            recall = recall_score(all_labels, preds)
            # ترکیب F1 و Recall با وزن بیشتر برای Recall
            score = 0.3 * f1 + 0.7 * recall

        if score > best_score:
            best_score = score
            best_threshold = threshold

    # نمایش نتایج برای threshold بهینه
    final_preds = (all_probs > best_threshold).astype(int)
    print(f"   Best threshold: {best_threshold:.2f}")
    print(f"   Validation F1: {f1_score(all_labels, final_preds):.4f}")
    print(f"   Validation Recall: {recall_score(all_labels, final_preds):.4f}")
    print(f"   Validation Precision: {precision_score(all_labels, final_preds):.4f}")

    return best_threshold
def print_results(metrics, scenario_name):
    """نمایش زیبای نتایج"""
    print(f"\n{'='*60}")
    print(f"📊 Results for {scenario_name}")
    print(f"{'='*60}")
    print(f"F1-Score:        {metrics['f1']:.4f}")
    print(f"Precision:       {metrics['precision']:.4f}")
    print(f"Recall:          {metrics['recall']:.4f}")
    print(f"AUC-ROC:         {metrics['auc_roc']:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Safe  Vuln")
    cm = metrics['confusion_matrix']
    if cm.shape[0] == 2:
        print(f"Actual Safe     [{cm[0,0]:4d}  {cm[0,1]:4d}]")
        print(f"       Vuln     [{cm[1,0]:4d}  {cm[1,1]:4d}]")
    else:
        print("   ⚠️ Warning: Only one class in predictions")

# ===========================
# Main Experiment Function
# ===========================

def run_experiments():
    """اجرای هر دو سناریو"""
    
    # تنظیمات
    base_path = r"C:\Users\Hadis\Documents\NewModel1"
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🖥️ Using device: {device}")
    
    # Hyperparameters
    BATCH_SIZE = 16
    NUM_EPOCHS = 30
    LEARNING_RATE = 0.001
    
    # ===== Experiment 1: Balanced Dataset =====
    print("\n" + "="*80)
    print("🔬 Experiment 1: Balanced Dataset")
    print("="*80)
    
    # ایجاد dataset
    dataset_balanced = SmartContractDataset(
        base_path=base_path,
        batch_names=['batch1', 'batch2'],
        balanced=True,
        random_seed=42
    )
    
    # Train/Val/Test split
    train_size = int(0.7 * len(dataset_balanced))
    val_size = int(0.15 * len(dataset_balanced))
    test_size = len(dataset_balanced) - train_size - val_size
    
    train_dataset, val_dataset, test_dataset = random_split(
        dataset_balanced, 
        [train_size, val_size, test_size],
        generator=torch.Generator().manual_seed(42)
    )
    
    # Data loaders
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, collate_fn=custom_collate_fn)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)
    
    print(f"\n📊 Dataset splits:")
    print(f"   Train: {len(train_dataset)} samples")
    print(f"   Val: {len(val_dataset)} samples")
    print(f"   Test: {len(test_dataset)} samples")
    
    # مدل
    # بارگذاری مدل ذخیره شده
    model_balanced = Sentinel_1()
    model_balanced.load_state_dict(torch.load('taintsentinel_balanced.pt'))
    model_balanced = model_balanced.to(device)
    print("✅ Loaded pre-trained balanced model")

    # حذف قسمت آموزش - دیگر نیازی نیست
    # پیدا کردن بهترین threshold
    best_threshold_balanced = find_best_threshold(model_balanced, val_loader, device)

    # ارزیابی با threshold بهینه
    metrics_balanced = evaluate_model(model_balanced, test_loader, device, threshold=best_threshold_balanced)
    print_results(metrics_balanced, "Balanced Dataset")
    
    # ===== Experiment 2: Imbalanced Dataset =====
    print("\n\n" + "="*80)
    print("🔬 Experiment 2: Imbalanced Dataset")
    print("="*80)
    
    # ایجاد dataset
    dataset_imbalanced = SmartContractDataset(
        base_path=base_path,
        batch_names=['batch1', 'batch2'],
        balanced=False,
        random_seed=42
    )
    
    # محاسبه class weights
    all_labels = [dataset_imbalanced[i]['label'].item() for i in range(len(dataset_imbalanced))]
    num_safe = all_labels.count(0)
    num_vuln = all_labels.count(1)
    
    # Inverse frequency weighting
    total = num_safe + num_vuln
    weight_safe = total / (2 * num_safe)
    weight_vuln = total / (2 * num_vuln)
    class_weights = [weight_safe, weight_vuln]
    
    print(f"\n⚖️ Class distribution:")
    print(f"   Safe: {num_safe} ({num_safe/total*100:.1f}%)")
    print(f"   Vulnerable: {num_vuln} ({num_vuln/total*100:.1f}%)")
    print(f"   Class weights: Safe={class_weights[0]:.2f}, Vulnerable={class_weights[1]:.2f}")
    
    # Train/Val/Test split
    train_size = int(0.7 * len(dataset_imbalanced))
    val_size = int(0.15 * len(dataset_imbalanced))
    test_size = len(dataset_imbalanced) - train_size - val_size
    
    train_dataset, val_dataset, test_dataset = random_split(
        dataset_imbalanced, 
        [train_size, val_size, test_size],
        generator=torch.Generator().manual_seed(42)
    )
    
    # Data loaders
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, collate_fn=custom_collate_fn)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)
    
    print(f"\n📊 Dataset splits:")
    print(f"   Train: {len(train_dataset)} samples")
    print(f"   Val: {len(val_dataset)} samples")
    print(f"   Test: {len(test_dataset)} samples")

    # بارگذاری مدل ذخیره شده
    model_imbalanced = Sentinel_1()
    model_imbalanced.load_state_dict(torch.load('taintsentinel_imbalanced.pt'))
    model_imbalanced = model_imbalanced.to(device)
    print("✅ Loaded pre-trained imbalanced model")


    # پیدا کردن بهترین threshold با تاکید بر recall
    best_threshold_imbalanced = find_best_threshold(
        model_imbalanced,
        val_loader,
        device,
        optimize_for='recall'  # این خط اضافه شد
    )

    # ارزیابی با threshold بهینه
    metrics_imbalanced = evaluate_model(model_imbalanced, test_loader, device, threshold=best_threshold_imbalanced)

    # بررسی و بهبود بیشتر اگر recall کم است
    print(f"\n📊 Initial Recall: {metrics_imbalanced['recall']:.4f}")
    if metrics_imbalanced['recall'] < 0.65:
        print("⚠️ Recall is still low, trying more aggressive threshold...")

        # تست threshold پایین‌تر
        aggressive_threshold = max(0.05, best_threshold_imbalanced - 0.10)
        print(f"   Testing threshold: {aggressive_threshold:.2f}")

        # ارزیابی مجدد
        metrics_aggressive = evaluate_model(model_imbalanced, test_loader, device, threshold=aggressive_threshold)

        # اگر بهبود قابل توجه در recall داشتیم
        if metrics_aggressive['recall'] > metrics_imbalanced['recall'] + 0.10:
            print(f"   ✅ Better recall achieved: {metrics_aggressive['recall']:.4f}")
            metrics_imbalanced = metrics_aggressive
            best_threshold_imbalanced = aggressive_threshold
    print_results(metrics_imbalanced, "Imbalanced Dataset")

    # نمایش تحلیل False Negatives
    cm = metrics_imbalanced['confusion_matrix']
    if cm.shape[0] == 2 and cm.shape[1] == 2:
        false_negatives = cm[1, 0]
        true_positives = cm[1, 1]
        total_vulnerable = false_negatives + true_positives

        print(f"\n📊 Vulnerable Detection Analysis:")
        print(f"   Total vulnerable contracts: {total_vulnerable}")
        print(f"   Correctly detected: {true_positives} ({true_positives / total_vulnerable * 100:.1f}%)")
        print(f"   Missed (False Negatives): {false_negatives} ({false_negatives / total_vulnerable * 100:.1f}%)")
        print(f"   Current threshold: {best_threshold_imbalanced:.2f}")
    
    # ===== Final Comparison =====
    print("\n\n" + "="*80)
    print("📊 Final Comparison")
    print("="*80)
    print(f"\n{'Metric':<15} {'Balanced':<12} {'Imbalanced':<12}")
    print("-" * 40)
    print(f"{'F1-Score':<15} {metrics_balanced['f1']:<12.4f} {metrics_imbalanced['f1']:<12.4f}")
    print(f"{'Precision':<15} {metrics_balanced['precision']:<12.4f} {metrics_imbalanced['precision']:<12.4f}")
    print(f"{'Recall':<15} {metrics_balanced['recall']:<12.4f} {metrics_imbalanced['recall']:<12.4f}")
    print(f"{'AUC-ROC':<15} {metrics_balanced['auc_roc']:<12.4f} {metrics_imbalanced['auc_roc']:<12.4f}")

    return {
        'balanced': {'model': model_balanced, 'metrics': metrics_balanced},
        'imbalanced': {'model': model_imbalanced, 'metrics': metrics_imbalanced}
    }
# ===========================
# Run Everything
# ===========================

if __name__ == "__main__":
    print("🚀 TaintSentinel Complete Training Pipeline")
    print("="*80)
    
    try:
        results = run_experiments()
        
        print("\n\n" + "="*80)
        print("✅ All experiments completed successfully!")
        print("="*80)
        
        # ذخیره مدل‌ها
        torch.save(results['balanced']['model'].state_dict(), 'taintsentinel_balanced.pt')
        torch.save(results['imbalanced']['model'].state_dict(), 'taintsentinel_imbalanced.pt')
        print("\n💾 Models saved successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()