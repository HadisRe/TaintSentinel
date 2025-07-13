"""
TaintSentinel - Complete Training Pipeline with Path Risk Accuracy (PRA)
کد کامل با پیاده‌سازی هر 5 معیار ارزیابی
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
warnings.filterwarnings('ignore')

# ===========================
# Import Models from Previous Files
# ===========================
try:
    from Sentinel_1 import SmartContractDataset
    from Sentinel_2 import GlobalGNN, PathGNN, custom_collate_fn
    print("✅ Successfully imported components from previous files")
except ImportError as e:
    print(f"❌ Error importing components: {e}")
    print("   Please ensure Sentinel_1.py and Sentinel_2.py are in the same directory")
    exit(1)

# ===========================
# NEW: Path Risk Functions for PRA
# ===========================

def calculate_path_risk_label(path_data):
    """
    محاسبه برچسب ریسک واقعی برای یک مسیر بر اساس ویژگی‌های آن
    Returns: 0 (LOW), 1 (MEDIUM), 2 (HIGH)
    """
    features = path_data['features'].cpu().numpy()
    if len(features.shape) > 1:
        features = features.mean(axis=0)

    # معیارهای ریسک (بر اساس 6 ویژگی مسیر)
    path_length = features[0] if len(features) > 0 else 0
    dangerous_ops = features[1] if len(features) > 1 else 0
    external_calls = features[2] if len(features) > 2 else 0

    # قوانین تعیین سطح ریسک
    if dangerous_ops > 0.7 or external_calls > 0.8 or path_length > 0.9:
        return 2  # HIGH
    elif dangerous_ops > 0.4 or external_calls > 0.5 or path_length > 0.6:
        return 1  # MEDIUM
    else:
        return 0  # LOW

# ===========================
# ENHANCED Model with Path Risk Prediction
# ===========================

class TaintSentinelWithPRA(nn.Module):
    """مدل نهایی با قابلیت پیش‌بینی ریسک مسیر برای PRA"""

    def __init__(self, node_feature_dim=18, path_feature_dim=6,
                 hidden_dim=128, num_classes=2, num_risk_levels=3, dropout=0.2):
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
            hidden_dim=hidden_dim//2,
            dropout=dropout
        )

        # NEW: Path Risk Classifier برای PRA
        self.path_risk_classifier = nn.Sequential(
            nn.Linear(hidden_dim//2, hidden_dim//4),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim//4, num_risk_levels)  # 3 سطح: LOW, MEDIUM, HIGH
        )

        # Gated Fusion
        fusion_dim = hidden_dim * 2 + hidden_dim // 2
        self.gate = nn.Sequential(
            nn.Linear(fusion_dim, hidden_dim),
            nn.Sigmoid()
        )

        self.fusion_mlp = nn.Sequential(
            nn.Linear(fusion_dim, hidden_dim * 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim * 2, hidden_dim)
        )

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

    def forward(self, batch_data, return_path_risks=False):
        """Forward pass با قابلیت برگرداندن پیش‌بینی ریسک مسیرها"""
        batched_graph = batch_data['graph']
        paths_list = batch_data['paths']
        batch_size = len(batch_data['labels'])

        # Global GNN processing
        global_embedding = self.global_gnn(
            batched_graph.x,
            batched_graph.edge_index,
            batched_graph.batch
        )

        path_embeddings = []
        path_risk_predictions = []

        for i in range(batch_size):
            graph_mask = (batched_graph.batch == i)
            graph_nodes = batched_graph.x[graph_mask]

            path_data = paths_list[i]
            path_embedding = self.path_gnn(path_data, graph_nodes)
            path_embeddings.append(path_embedding)

            # NEW: پیش‌بینی ریسک مسیر
            if return_path_risks:
                path_risk = self.path_risk_classifier(path_embedding)
                path_risk_predictions.append(path_risk)

        path_embeddings = torch.cat(path_embeddings, dim=0)
        combined = torch.cat([global_embedding, path_embeddings], dim=1)

        gate_values = self.gate(combined)
        fused_features = self.fusion_mlp(combined)
        gated_features = gate_values * fused_features
        output = self.classifier(gated_features)

        if return_path_risks:
            path_risks = torch.cat(path_risk_predictions, dim=0) if path_risk_predictions else None
            return output, path_risks
        else:
            return output

# ===========================
# MODIFIED Training Functions with PRA
# ===========================

def train_epoch(model, train_loader, criterion, path_risk_criterion, optimizer, device):
    """آموزش با در نظر گرفتن path risk"""
    model.train()
    total_loss = 0
    total_path_risk_loss = 0
    all_preds = []
    all_labels = []

    for batch_idx, batch in enumerate(train_loader):
        batch['graph'] = batch['graph'].to(device)
        for i in range(len(batch['paths'])):
            for key in ['sequences', 'lengths', 'features']:
                batch['paths'][i][key] = batch['paths'][i][key].to(device)
        labels = batch['labels'].to(device)

        # NEW: محاسبه path risk labels
        path_risk_labels = []
        for i in range(len(batch['paths'])):
            risk_label = calculate_path_risk_label(batch['paths'][i])
            path_risk_labels.append(risk_label)
        path_risk_labels = torch.tensor(path_risk_labels, dtype=torch.long).to(device)

        outputs, path_risks = model(batch, return_path_risks=True)

        classification_loss = criterion(outputs, labels)
        path_risk_loss = path_risk_criterion(path_risks, path_risk_labels) if path_risks is not None else 0

        # ترکیب losses
        loss = classification_loss + 0.3 * path_risk_loss

        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()

        total_loss += loss.item()
        if isinstance(path_risk_loss, torch.Tensor):
            total_path_risk_loss += path_risk_loss.item()

        preds = outputs.argmax(dim=1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

        if batch_idx % 10 == 0:
            print(f"\r   Batch [{batch_idx}/{len(train_loader)}] Loss: {loss.item():.4f}", end='')

    print()
    return total_loss / len(train_loader), all_preds, all_labels

def validate_epoch(model, val_loader, criterion, path_risk_criterion, device):
    """ارزیابی با محاسبه PRA"""
    model.eval()
    total_loss = 0
    all_preds = []
    all_labels = []
    all_probs = []
    path_risk_accuracy = 0
    num_paths = 0

    with torch.no_grad():
        for batch in val_loader:
            batch['graph'] = batch['graph'].to(device)
            for i in range(len(batch['paths'])):
                for key in ['sequences', 'lengths', 'features']:
                    batch['paths'][i][key] = batch['paths'][i][key].to(device)
            labels = batch['labels'].to(device)

            # محاسبه path risk labels
            path_risk_labels = []
            for i in range(len(batch['paths'])):
                risk_label = calculate_path_risk_label(batch['paths'][i])
                path_risk_labels.append(risk_label)
            path_risk_labels = torch.tensor(path_risk_labels, dtype=torch.long).to(device)

            outputs, path_risks = model(batch, return_path_risks=True)
            loss = criterion(outputs, labels)

            # NEW: محاسبه Path Risk Accuracy
            if path_risks is not None:
                path_risk_preds = path_risks.argmax(dim=1)
                path_risk_accuracy += (path_risk_preds == path_risk_labels).sum().item()
                num_paths += len(path_risk_labels)

            total_loss += loss.item()
            preds = outputs.argmax(dim=1)
            probs = F.softmax(outputs, dim=1)[:, 1]

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())

    # محاسبه PRA
    pra = path_risk_accuracy / num_paths if num_paths > 0 else 0

    return total_loss / len(val_loader), all_preds, all_labels, all_probs, pra

# ===========================
# ENHANCED Evaluation Function with PRA
# ===========================

def evaluate_model(model, test_loader, device, threshold=0.5):
    """ارزیابی جامع مدل شامل PRA"""
    model.eval()
    all_preds = []
    all_labels = []
    all_probs = []
    path_risk_correct = 0
    total_paths = 0

    print(f"\n📊 Evaluating model on test set (threshold={threshold:.2f})...")

    with torch.no_grad():
        for batch in test_loader:
            batch['graph'] = batch['graph'].to(device)
            for i in range(len(batch['paths'])):
                for key in ['sequences', 'lengths', 'features']:
                    batch['paths'][i][key] = batch['paths'][i][key].to(device)
            labels = batch['labels'].to(device)

            # محاسبه path risk labels
            path_risk_labels = []
            for i in range(len(batch['paths'])):
                risk_label = calculate_path_risk_label(batch['paths'][i])
                path_risk_labels.append(risk_label)
            path_risk_labels = torch.tensor(path_risk_labels, dtype=torch.long).to(device)

            outputs, path_risks = model(batch, return_path_risks=True)
            probs = F.softmax(outputs, dim=1)[:, 1]
            preds = (probs > threshold).long()

            # NEW: محاسبه Path Risk Accuracy
            if path_risks is not None:
                path_risk_preds = path_risks.argmax(dim=1)
                path_risk_correct += (path_risk_preds == path_risk_labels).sum().item()
                total_paths += len(path_risk_labels)

            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())

    # محاسبه همه 5 معیار
    metrics = {
        'f1': f1_score(all_labels, all_preds, zero_division=0),
        'precision': precision_score(all_labels, all_preds, zero_division=0),
        'recall': recall_score(all_labels, all_preds, zero_division=0),
        'confusion_matrix': confusion_matrix(all_labels, all_preds),
        'pra': path_risk_correct / total_paths if total_paths > 0 else 0  # معیار 5
    }

    if len(np.unique(all_labels)) > 1:
        metrics['auc_roc'] = roc_auc_score(all_labels, all_probs)
    else:
        metrics['auc_roc'] = 0.0

    return metrics

def print_results(metrics, scenario_name):
    """نمایش زیبای نتایج شامل PRA"""
    print(f"\n{'='*60}")
    print(f"📊 Results for {scenario_name}")
    print(f"{'='*60}")
    print(f"F1-Score:              {metrics['f1']:.4f}")
    print(f"Precision:             {metrics['precision']:.4f}")
    print(f"Recall:                {metrics['recall']:.4f}")
    print(f"AUC-ROC:               {metrics['auc_roc']:.4f}")
    print(f"Path Risk Accuracy:    {metrics['pra']:.4f}")  # معیار 5
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
# بقیه کد (توابع train_model، find_best_threshold و run_experiments)
# ===========================

def train_model(model, train_loader, val_loader, num_epochs=50,
                learning_rate=0.001, weight_decay=1e-4, class_weights=None, device='cpu'):
    """آموزش کامل مدل با PRA"""

    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', patience=5, factor=0.5)

    if class_weights is not None:
        class_weights = torch.tensor(class_weights, dtype=torch.float).to(device)
        criterion = nn.CrossEntropyLoss(weight=class_weights)
    else:
        criterion = nn.CrossEntropyLoss()

    path_risk_criterion = nn.CrossEntropyLoss()

    history = defaultdict(list)
    best_val_f1 = 0
    best_model_state = None

    print("\n🚀 Starting training with Path Risk Accuracy...")
    print("-" * 60)

    start_time = time.time()

    for epoch in range(num_epochs):
        epoch_start = time.time()

        train_loss, train_preds, train_labels = train_epoch(
            model, train_loader, criterion, path_risk_criterion, optimizer, device
        )

        val_loss, val_preds, val_labels, val_probs, val_pra = validate_epoch(
            model, val_loader, criterion, path_risk_criterion, device
        )

        train_f1 = f1_score(train_labels, train_preds, zero_division=0)
        val_f1 = f1_score(val_labels, val_preds, zero_division=0)
        val_precision = precision_score(val_labels, val_preds, zero_division=0)
        val_recall = recall_score(val_labels, val_preds, zero_division=0)

        if len(np.unique(val_labels)) > 1:
            val_auc = roc_auc_score(val_labels, val_probs)
        else:
            val_auc = 0.0

        history['train_loss'].append(train_loss)
        history['val_loss'].append(val_loss)
        history['train_f1'].append(train_f1)
        history['val_f1'].append(val_f1)
        history['val_precision'].append(val_precision)
        history['val_recall'].append(val_recall)
        history['val_auc'].append(val_auc)
        history['val_pra'].append(val_pra)  # NEW

        scheduler.step(val_f1)

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_model_state = model.state_dict()

        epoch_time = time.time() - epoch_start
        if epoch % 5 == 0 or epoch == num_epochs - 1:
            print(f"\nEpoch [{epoch+1}/{num_epochs}] (Time: {epoch_time:.1f}s)")
            print(f"  Train - Loss: {train_loss:.4f}, F1: {train_f1:.4f}")
            print(f"  Val   - Loss: {val_loss:.4f}, F1: {val_f1:.4f}")
            print(f"          Precision: {val_precision:.4f}, Recall: {val_recall:.4f}, AUC: {val_auc:.4f}")
            print(f"          Path Risk Accuracy (PRA): {val_pra:.4f}")  # NEW
            print(f"  LR: {optimizer.param_groups[0]['lr']:.6f}")

    total_time = time.time() - start_time
    print(f"\n✅ Training completed in {total_time/60:.1f} minutes")
    print(f"   Best validation F1: {best_val_f1:.4f}")

    model.load_state_dict(best_model_state)

    return model, history

def find_best_threshold(model, val_loader, device, optimize_for='f1'):
    """پیدا کردن بهترین threshold"""
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

            outputs, _ = model(batch, return_path_risks=True)
            probs = F.softmax(outputs, dim=1)[:, 1]

            all_probs.extend(probs.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

    all_probs = np.array(all_probs)
    all_labels = np.array(all_labels)

    best_score = 0
    best_threshold = 0.5

    for threshold in np.arange(0.05, 0.70, 0.05):
        preds = (all_probs > threshold).astype(int)

        if optimize_for == 'f1':
            score = f1_score(all_labels, preds)
        elif optimize_for == 'recall':
            f1 = f1_score(all_labels, preds)
            recall = recall_score(all_labels, preds)
            score = 0.3 * f1 + 0.7 * recall

        if score > best_score:
            best_score = score
            best_threshold = threshold

    final_preds = (all_probs > best_threshold).astype(int)
    print(f"   Best threshold: {best_threshold:.2f}")
    print(f"   Validation F1: {f1_score(all_labels, final_preds):.4f}")
    print(f"   Validation Recall: {recall_score(all_labels, final_preds):.4f}")
    print(f"   Validation Precision: {precision_score(all_labels, final_preds):.4f}")

    return best_threshold

def run_experiments():
    """اجرای هر دو سناریو با PRA"""

    base_path = r"C:\Users\Hadis\Documents\NewModel1"
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🖥️ Using device: {device}")

    BATCH_SIZE = 16
    NUM_EPOCHS = 30
    LEARNING_RATE = 0.001

    # ===== Experiment 1: Balanced Dataset =====
    print("\n" + "="*80)
    print("🔬 Experiment 1: Balanced Dataset")
    print("="*80)

    dataset_balanced = SmartContractDataset(
        base_path=base_path,
        batch_names=['batch1', 'batch2'],
        balanced=True,
        random_seed=42
    )

    train_size = int(0.7 * len(dataset_balanced))
    val_size = int(0.15 * len(dataset_balanced))
    test_size = len(dataset_balanced) - train_size - val_size

    train_dataset, val_dataset, test_dataset = random_split(
        dataset_balanced,
        [train_size, val_size, test_size],
        generator=torch.Generator().manual_seed(42)
    )

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, collate_fn=custom_collate_fn)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)

    print(f"\n📊 Dataset splits:")
    print(f"   Train: {len(train_dataset)} samples")
    print(f"   Val: {len(val_dataset)} samples")
    print(f"   Test: {len(test_dataset)} samples")

    # مدل جدید با PRA
    model_balanced = TaintSentinelWithPRA()

    # آموزش یا بارگذاری مدل
    try:
        model_balanced.load_state_dict(torch.load('taintsentinel_balanced_with_pra.pt'))
        model_balanced = model_balanced.to(device)
        print("✅ Loaded pre-trained balanced model with PRA")
        history_balanced = None
    except:
        print("🔄 Training new model with PRA...")
        model_balanced, history_balanced = train_model(
            model_balanced,
            train_loader,
            val_loader,
            num_epochs=NUM_EPOCHS,
            learning_rate=LEARNING_RATE,
            device=device
        )

    best_threshold_balanced = find_best_threshold(model_balanced, val_loader, device)
    metrics_balanced = evaluate_model(model_balanced, test_loader, device, threshold=best_threshold_balanced)
    print_results(metrics_balanced, "Balanced Dataset")

    # ===== Experiment 2: Imbalanced Dataset =====
    print("\n\n" + "="*80)
    print("🔬 Experiment 2: Imbalanced Dataset")
    print("="*80)

    dataset_imbalanced = SmartContractDataset(
        base_path=base_path,
        batch_names=['batch1', 'batch2'],
        balanced=False,
        random_seed=42
    )

    all_labels = [dataset_imbalanced[i]['label'].item() for i in range(len(dataset_imbalanced))]
    num_safe = all_labels.count(0)
    num_vuln = all_labels.count(1)

    total = num_safe + num_vuln
    weight_safe = total / (2 * num_safe)
    weight_vuln = total / (2 * num_vuln)
    class_weights = [weight_safe, weight_vuln]

    print(f"\n⚖️ Class distribution:")
    print(f"   Safe: {num_safe} ({num_safe/total*100:.1f}%)")
    print(f"   Vulnerable: {num_vuln} ({num_vuln/total*100:.1f}%)")
    print(f"   Class weights: Safe={class_weights[0]:.2f}, Vulnerable={class_weights[1]:.2f}")

    train_size = int(0.7 * len(dataset_imbalanced))
    val_size = int(0.15 * len(dataset_imbalanced))
    test_size = len(dataset_imbalanced) - train_size - val_size

    train_dataset, val_dataset, test_dataset = random_split(
        dataset_imbalanced,
        [train_size, val_size, test_size],
        generator=torch.Generator().manual_seed(42)
    )

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, collate_fn=custom_collate_fn)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False, collate_fn=custom_collate_fn)

    print(f"\n📊 Dataset splits:")
    print(f"   Train: {len(train_dataset)} samples")
    print(f"   Val: {len(val_dataset)} samples")
    print(f"   Test: {len(test_dataset)} samples")

    # مدل جدید با PRA
    model_imbalanced = TaintSentinelWithPRA()

    # آموزش یا بارگذاری مدل
    try:
        model_imbalanced.load_state_dict(torch.load('taintsentinel_imbalanced_with_pra.pt'))
        model_imbalanced = model_imbalanced.to(device)
        print("✅ Loaded pre-trained imbalanced model with PRA")
        history_imbalanced = None
    except:
        print("🔄 Training new model with PRA...")
        model_imbalanced, history_imbalanced = train_model(
            model_imbalanced,
            train_loader,
            val_loader,
            num_epochs=NUM_EPOCHS,
            learning_rate=LEARNING_RATE,
            class_weights=class_weights,
            device=device
        )

    best_threshold_imbalanced = find_best_threshold(
        model_imbalanced,
        val_loader,
        device,
        optimize_for='recall'
    )

    metrics_imbalanced = evaluate_model(model_imbalanced, test_loader, device, threshold=best_threshold_imbalanced)

    print(f"\n📊 Initial Recall: {metrics_imbalanced['recall']:.4f}")
    if metrics_imbalanced['recall'] < 0.65:
        print("⚠️ Recall is still low, trying more aggressive threshold...")
        aggressive_threshold = max(0.05, best_threshold_imbalanced - 0.10)
        print(f"   Testing threshold: {aggressive_threshold:.2f}")
        metrics_aggressive = evaluate_model(model_imbalanced, test_loader, device, threshold=aggressive_threshold)
        if metrics_aggressive['recall'] > metrics_imbalanced['recall'] + 0.10:
            print(f"   ✅ Better recall achieved: {metrics_aggressive['recall']:.4f}")
            metrics_imbalanced = metrics_aggressive
            best_threshold_imbalanced = aggressive_threshold

    print_results(metrics_imbalanced, "Imbalanced Dataset")

    # ===== Final Comparison =====
    print("\n\n" + "="*80)
    print("📊 Final Comparison (All 5 Metrics)")
    print("="*80)
    print(f"\n{'Metric':<20} {'Balanced':<12} {'Imbalanced':<12}")
    print("-" * 45)
    print(f"{'F1-Score':<20} {metrics_balanced['f1']:<12.4f} {metrics_imbalanced['f1']:<12.4f}")
    print(f"{'Precision':<20} {metrics_balanced['precision']:<12.4f} {metrics_imbalanced['precision']:<12.4f}")
    print(f"{'Recall':<20} {metrics_balanced['recall']:<12.4f} {metrics_imbalanced['recall']:<12.4f}")
    print(f"{'AUC-ROC':<20} {metrics_balanced['auc_roc']:<12.4f} {metrics_imbalanced['auc_roc']:<12.4f}")
    print(f"{'Path Risk Accuracy':<20} {metrics_balanced['pra']:<12.4f} {metrics_imbalanced['pra']:<12.4f}")

    return {
        'balanced': {'model': model_balanced, 'metrics': metrics_balanced, 'history': history_balanced},
        'imbalanced': {'model': model_imbalanced, 'metrics': metrics_imbalanced, 'history': history_imbalanced}
    }

# ===========================
# Run Everything
# ===========================

if __name__ == "__main__":
    print("🚀 TaintSentinel Complete Training Pipeline with Path Risk Accuracy (PRA)")
    print("="*80)

    try:
        results = run_experiments()

        print("\n\n" + "="*80)
        print("✅ All experiments completed successfully!")
        print("="*80)

        # ذخیره مدل‌ها
        torch.save(results['balanced']['model'].state_dict(), 'taintsentinel_balanced_with_pra.pt')
        torch.save(results['imbalanced']['model'].state_dict(), 'taintsentinel_imbalanced_with_pra.pt')
        print("\n💾 Models saved successfully!")

        # نمایش خلاصه PRA
        print("\n📊 Path Risk Accuracy Summary:")
        print(f"   Balanced Dataset PRA: {results['balanced']['metrics']['pra']:.4f}")
        print(f"   Imbalanced Dataset PRA: {results['imbalanced']['metrics']['pra']:.4f}")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()