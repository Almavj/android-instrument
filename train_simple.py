#!/usr/bin/env python3
"""Train a RandomForest malware/behavior classifier from features.json.

By default refuses to invent labels. Optional --allow-synth-augment expands a
tiny real dataset for smoke-testing only (never for published metrics).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


def load_xy(path: str):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    feature_names = data["feature_names"]
    X, y = [], []
    for sample in data.get("samples", []):
        feats = sample.get("features", {})
        X.append([float(feats.get(name, 0.0)) for name in feature_names])
        y.append(str(sample.get("label", "unknown")))
    return feature_names, np.array(X, dtype=np.float64), np.array(y)


def synth_augment(X, y, n_per_class: int = 40, seed: int = 42):
    """Smoke-test only: create noisy clones. Marks labels with synth: prefix."""
    rng = np.random.default_rng(seed)
    X_out, y_out = [X.copy()], [y.copy()]
    if len(X) == 0:
        return X, y
    base = X[0]
    # create two buckets around first sample
    for _ in range(n_per_class):
        X_out.append((base + rng.normal(0, 0.35, size=base.shape)).reshape(1, -1))
        y_out.append(np.array(["synth:benign"]))
        X_out.append((base + rng.normal(1.5, 0.6, size=base.shape)).reshape(1, -1))
        y_out.append(np.array(["synth:malware"]))
    return np.vstack(X_out), np.concatenate(y_out)


def main():
    parser = argparse.ArgumentParser(description="Train RandomForest on behavioral features")
    parser.add_argument("--features", default="features.json")
    parser.add_argument("--output", default="model_rf.pkl")
    parser.add_argument("--allow-synth-augment", action="store_true",
                        help="Allow synthetic augmentation for smoke tests only")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if not Path(args.features).is_file():
        print(f"[!] Features not found: {args.features}")
        sys.exit(2)

    feature_names, X, y = load_xy(args.features)
    print(f"[*] Dataset: {len(X)} samples, {len(feature_names)} features")
    print(f"[*] Labels: {dict(Counter(y))}")

    used_synth = False
    if len(X) < 4 or len(set(y)) < 2:
        if not args.allow_synth_augment:
            print("[!] Need >=4 samples and >=2 classes for real training.")
            print("    Re-run with --allow-synth-augment for smoke-test only,")
            print("    or provide a multi-sample labeled features.json.")
            # still dump a fitted model on single class if possible
            if len(X) == 0:
                sys.exit(1)
            clf = RandomForestClassifier(n_estimators=50, random_state=args.seed)
            # duplicate rows to satisfy RF
            X_fit = np.vstack([X, X])
            y_fit = np.concatenate([y, y])
            clf.fit(X_fit, y_fit)
            joblib.dump({"model": clf, "feature_names": feature_names, "synthetic": False},
                        args.output)
            print(f"[+] Saved minimal model: {args.output}")
            return
        print("[!] WARNING: synthetic augmentation enabled — metrics are NOT scientific")
        X, y = synth_augment(X, y, seed=args.seed)
        used_synth = True
        print(f"[*] Augmented dataset: {len(X)} samples, labels={dict(Counter(y))}")

    strat = y if len(set(y)) > 1 else None
    # Can't stratify if any class has fewer than 2 samples
    if strat is not None:
        counts = Counter(strat)
        if min(counts.values()) < 2:
            strat = None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=strat
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=args.seed,
        class_weight="balanced_subsample",
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[*] Accuracy: {acc:.2%}" + (" (SYNTHETIC)" if used_synth else ""))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    print("Feature importance (top 15):")
    order = np.argsort(clf.feature_importances_)[::-1][:15]
    for idx in order:
        if idx < len(feature_names):
            print(f"  {feature_names[idx]}: {clf.feature_importances_[idx]:.4f}")

    payload = {
        "model": clf,
        "feature_names": feature_names,
        "synthetic": used_synth,
        "accuracy": float(acc),
        "labels": sorted(set(y.tolist())),
    }
    joblib.dump(payload, args.output)
    print(f"\n[+] Model saved: {args.output}")


if __name__ == "__main__":
    main()
