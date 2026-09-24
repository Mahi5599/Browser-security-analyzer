"""Train the phishing URL classifier (Random Forest).

Usage:
    python -m ml.train_model                 # auto: PhiUSIIL, else sample
    python -m ml.train_model --source sample # force the bundled dataset
    python -m ml.train_model --max-rows 60000

Outputs:
    app/models/phishing_model.pkl   -- joblib bundle {model, feature_names, meta}
    ml/dataset/train.csv, test.csv  -- the exact split (evaluate.py reads test.csv)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.phishing_features import URL_FEATURE_NAMES  # noqa: E402
from ml.data_loader import build_feature_frame, load_labelled_urls  # noqa: E402

HERE = os.path.dirname(__file__)
MODEL_OUT = os.path.join(HERE, "..", "app", "models", "phishing_model.pkl")
TRAIN_CSV = os.path.join(HERE, "dataset", "train.csv")
TEST_CSV = os.path.join(HERE, "dataset", "test.csv")
RANDOM_STATE = 42


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["auto", "phiusiil", "sample"], default="auto")
    ap.add_argument("--no-augment", action="store_true",
                    help="disable benign path/scheme augmentation (PhiUSIIL only)")
    ap.add_argument("--max-rows", type=int, default=200000)
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=24)
    ap.add_argument("--min-samples-leaf", type=int, default=8)
    args = ap.parse_args()

    print(f"[train] loading dataset (source={args.source}) ...")
    df, source = load_labelled_urls(
        prefer=args.source, max_rows=args.max_rows, augment=not args.no_augment
    )
    print(f"[train] {len(df)} URLs from: {source}")
    print(f"[train] class balance: {df['label'].value_counts().to_dict()}")

    print("[train] extracting features ...")
    feat_df = build_feature_frame(df)

    X = feat_df[URL_FEATURE_NAMES].to_numpy(dtype=float)
    y = feat_df["label"].to_numpy(dtype=int)

    X_tr, X_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X, y, np.arange(len(y)), test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )

    print("[train] 5-fold CV on the training split ...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_proba = cross_val_predict(clf, X_tr, y_tr, cv=skf, method="predict_proba", n_jobs=-1)[:, 1]
    cv_pred = (cv_proba >= 0.5).astype(int)
    cv_metrics = {
        "precision": round(float(precision_score(y_tr, cv_pred)), 4),
        "recall": round(float(recall_score(y_tr, cv_pred)), 4),
        "f1": round(float(f1_score(y_tr, cv_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_tr, cv_proba)), 4),
        "pr_auc": round(float(average_precision_score(y_tr, cv_proba)), 4),
    }
    print(f"[train] CV metrics: {cv_metrics}")

    print("[train] fitting final model on the full training split ...")
    clf.fit(X_tr, y_tr)

    bundle = {
        "model": clf,
        "feature_names": URL_FEATURE_NAMES,
        "model_type": "RandomForestClassifier",
        "trained_at": dt.datetime.utcnow().isoformat() + "Z",
        "dataset": {
            "source": source,
            "n_total": int(len(df)),
            "n_train": int(len(y_tr)),
            "n_test": int(len(y_te)),
            "class_balance": {int(k): int(v) for k, v in df["label"].value_counts().items()},
        },
        "cv_metrics": cv_metrics,
        "params": clf.get_params(),
        "random_state": RANDOM_STATE,
    }

    os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
    joblib.dump(bundle, MODEL_OUT, compress=3)
    print(f"[train] saved model -> {os.path.relpath(MODEL_OUT)}")

    feat_df.iloc[idx_tr].to_csv(TRAIN_CSV, index=False)
    feat_df.iloc[idx_te].to_csv(TEST_CSV, index=False)
    print(f"[train] saved split -> {os.path.relpath(TRAIN_CSV)}, {os.path.relpath(TEST_CSV)}")

    print("\n[train] summary:\n" + json.dumps({k: bundle[k] for k in
          ["model_type", "trained_at", "dataset", "cv_metrics"]}, indent=2))


if __name__ == "__main__":
    main()
