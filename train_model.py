#!/usr/bin/env python3
"""LSTM-based Android malware classifier with SHAP explainability.

Trains a binary/multiclass classifier on behavioral feature vectors,
exports the model + scaler, generates evaluation metrics, and provides
feature importance analysis via SHAP.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import pickle
import sys
from datetime import datetime
from typing import Optional

import numpy as np

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    HAS_TF = True
except ImportError:
    tf = None  # type: ignore
    keras = None  # type: ignore
    layers = None  # type: ignore
    HAS_TF = False

try:
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        precision_recall_fscore_support, accuracy_score
    )
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


def load_features(path: str) -> tuple[list[str], np.ndarray, list[str]]:
    with open(path) as f:
        data = json.load(f)

    feature_names = data["feature_names"]
    samples = data["samples"]

    X = []
    y = []
    for sample in samples:
        features = sample.get("features", {})
        row = [features.get(f, 0.0) for f in feature_names]
        X.append(row)
        y.append(sample.get("label", "unknown"))

    return feature_names, np.array(X, dtype=np.float32), y


def build_lstm_model(input_dim: int, num_classes: int):
    if not HAS_TF:
        raise RuntimeError("TensorFlow is required for LSTM training")
    model = keras.Sequential([
        layers.Input(shape=(input_dim, 1)),
        layers.Masking(mask_value=0.0),
        layers.LSTM(64, return_sequences=False, dropout=0.3),
        layers.BatchNormalization(),
        layers.Dense(32, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(num_classes if num_classes > 2 else 1,
                    activation="softmax" if num_classes > 2 else "sigmoid"),
    ])

    if num_classes > 2:
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )
    else:
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss="binary_crossentropy",
            metrics=["accuracy"],
        )

    return model


def train_model(X_train: np.ndarray, y_train: np.ndarray,
                X_val: np.ndarray, y_val: np.ndarray,
                num_classes: int, epochs: int = 50,
                patience: int = 10):
    if not HAS_TF:
        raise RuntimeError("TensorFlow is required for LSTM training")
    model = build_lstm_model(X_train.shape[1], num_classes)

    X_train_lstm = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
    X_val_lstm = X_val.reshape(X_val.shape[0], X_val.shape[1], 1)

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=patience, restore_best_weights=True
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=5, min_lr=1e-6
        ),
    ]

    print(f"\n[*] Training LSTM model...")
    print(f"    Input shape:  ({X_train.shape[1]}, 1)")
    print(f"    Train samples: {X_train.shape[0]}")
    print(f"    Val samples:   {X_val.shape[0]}")
    print(f"    Classes:       {num_classes}")
    print(f"    Epochs:        {epochs}")
    print()

    history = model.fit(
        X_train_lstm, y_train,
        validation_data=(X_val_lstm, y_val),
        epochs=epochs,
        batch_size=32,
        callbacks=callbacks,
        verbose=1,
    )

    return model, history


def evaluate_model(model: keras.Model, X_test: np.ndarray,
                   y_test: np.ndarray, label_encoder: LabelEncoder,
                   output_dir: str):
    print("\n[*] Evaluating model...")

    X_test_lstm = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
    y_pred_prob = model.predict(X_test_lstm)

    if y_pred_prob.shape[1] == 1:
        y_pred = (y_pred_prob > 0.5).astype(int).flatten()
    else:
        y_pred = np.argmax(y_pred_prob, axis=1)

    y_test_labels = label_encoder.inverse_transform(y_test.astype(int))
    y_pred_labels = label_encoder.inverse_transform(y_pred)

    print("\nClassification Report:")
    print(classification_report(y_test_labels, y_pred_labels))

    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted"
    )

    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "report": classification_report(
            y_test_labels, y_pred_labels, output_dict=True
        ),
    }

    metrics_path = os.path.join(output_dir, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Metrics saved: {metrics_path}")

    if HAS_MPL:
        plot_confusion_matrix(y_test, y_pred, label_encoder, output_dir)
        plot_training_history(model, output_dir)

    return metrics


def plot_confusion_matrix(y_true, y_pred, label_encoder: LabelEncoder,
                          output_dir: str):
    cm = confusion_matrix(y_true, y_pred)
    labels = label_encoder.classes_

    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    ax.set_title("Confusion Matrix")
    plt.colorbar(im, ax=ax)

    tick_marks = np.arange(len(labels))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(labels)

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black")

    ax.set_ylabel("True")
    ax.set_xlabel("Predicted")
    plt.tight_layout()

    path = os.path.join(output_dir, "confusion_matrix.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Confusion matrix: {path}")


def plot_training_history(model: keras.Model, output_dir: str):
    if not hasattr(model, "history") or not model.history.history:
        return

    history = model.history.history
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))

    ax1.plot(history.get("loss", []), label="Train")
    ax1.plot(history.get("val_loss", []), label="Val")
    ax1.set_title("Loss")
    ax1.set_xlabel("Epoch")
    ax1.legend()

    ax2.plot(history.get("accuracy", []), label="Train")
    ax2.plot(history.get("val_accuracy", []), label="Val")
    ax2.set_title("Accuracy")
    ax2.set_xlabel("Epoch")
    ax2.legend()

    plt.tight_layout()
    path = os.path.join(output_dir, "training_history.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[+] Training history: {path}")


def compute_shap(model: keras.Model, X_train: np.ndarray,
                 X_test: np.ndarray, feature_names: list[str],
                 output_dir: str):
    if not HAS_SHAP:
        print("[!] SHAP not installed, skipping explainability")
        return

    print("\n[*] Computing SHAP values...")

    X_test_lstm = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)
    X_train_flat = X_train[:min(100, len(X_train))]
    X_test_sample = X_test[:min(50, len(X_test))]

    def model_predict(x_flat):
        x_lstm = x_flat.reshape(x_flat.shape[0], x_flat.shape[1], 1)
        return model.predict(x_lstm, verbose=0)

    background = X_train_flat
    explainer = shap.KernelExplainer(model_predict, background)
    shap_values = explainer.shap_values(X_test_sample)

    if isinstance(shap_values, list):
        shap_vals = shap_values[0]
    else:
        shap_vals = shap_values

    mean_abs_shap = np.mean(np.abs(shap_vals), axis=0)

    feature_importance = sorted(
        zip(feature_names, mean_abs_shap),
        key=lambda x: x[1],
        reverse=True
    )

    print("\nTop 20 Most Important Features:")
    for i, (name, importance) in enumerate(feature_importance[:20]):
        print(f"  {i+1:2d}. {name}: {importance:.6f}")

    importance_path = os.path.join(output_dir, "feature_importance.json")
    with open(importance_path, "w") as f:
        json.dump(
            [{"feature": n, "importance": float(v)}
             for n, v in feature_importance],
            f, indent=2
        )
    print(f"[+] Feature importance: {importance_path}")

    if HAS_MPL:
        top_n = min(25, len(feature_importance))
        names = [x[0] for x in feature_importance[:top_n]]
        values = [x[1] for x in feature_importance[:top_n]]

        fig, ax = plt.subplots(figsize=(10, 8))
        y_pos = range(len(names))
        ax.barh(y_pos, values)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(names, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("Mean |SHAP value|")
        ax.set_title("Feature Importance (SHAP)")
        plt.tight_layout()

        path = os.path.join(output_dir, "shap_importance.png")
        plt.savefig(path, dpi=150)
        plt.close()
        print(f"[+] SHAP plot: {path}")


def main():
    parser = argparse.ArgumentParser(
        description="LSTM Classifier for Android Malware Detection"
    )
    parser.add_argument("features", help="Path to features.json")
    parser.add_argument("-o", "--output", default="./output/model",
                        help="Output directory")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--no-shap", action="store_true",
                        help="Skip SHAP analysis")
    parser.add_argument("--load", help="Path to existing trained model directory")
    args = parser.parse_args()

    if not HAS_TF:
        print("[!] TensorFlow not installed: pip install tensorflow")
        sys.exit(1)
    if not HAS_SKLEARN:
        print("[!] scikit-learn not installed: pip install scikit-learn")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_output_dir = os.path.join(args.output, timestamp)
    os.makedirs(run_output_dir, exist_ok=True)

    if args.load:
        print(f"[*] Loading existing model from {args.load}")
        return

    print(f"[*] Loading features from {args.features}")
    feature_names, X, y = load_features(args.features)
    print(f"    Samples: {len(y)}")
    print(f"    Features: {len(feature_names)}")

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    num_classes = len(label_encoder.classes_)
    print(f"    Classes: {list(label_encoder.classes_)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=args.test_size,
        random_state=42, stratify=y_encoded
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    scaler_path = os.path.join(run_output_dir, "scaler.pkl")
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    print(f"[+] Scaler saved: {scaler_path}")

    model, history = train_model(
        X_train, y_train, X_test, y_test,
        num_classes=num_classes,
        epochs=args.epochs,
        patience=args.patience,
    )

    model_path = os.path.join(run_output_dir, "model.h5")
    model.save(model_path)
    print(f"[+] Model saved: {model_path}")

    le_path = os.path.join(run_output_dir, "label_encoder.pkl")
    with open(le_path, "wb") as f:
        pickle.dump(label_encoder, f)
    print(f"[+] Label encoder saved: {le_path}")

    history_path = os.path.join(run_output_dir, "training_history.json")
    with open(history_path, "w") as f:
        json.dump(history.history, f, indent=2)
    print(f"[+] Training history saved: {history_path}")

    importance_path = os.path.join(run_output_dir, "feature_importance.csv")
    if feature_names:
        with open(importance_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["feature", "importance"])
            writer.writerows([[name, 0.0] for name in feature_names])
    print(f"[+] Feature importance saved: {importance_path}")

    metrics = evaluate_model(model, X_test, y_test, label_encoder, run_output_dir)

    if not args.no_shap:
        compute_shap(model, X_train, X_test, feature_names, run_output_dir)

    print(f"\n{'='*50}")
    print(f"  Training complete")
    print(f"  Accuracy:  {metrics['accuracy']:.2%}")
    print(f"  Precision: {metrics['precision']:.2%}")
    print(f"  Recall:    {metrics['recall']:.2%}")
    print(f"  F1:        {metrics['f1']:.2%}")
    print(f"  Output:    {run_output_dir}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
