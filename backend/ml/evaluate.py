"""Evaluate the trained phishing model on the held-out test split.

Writes ``ml/metrics_report.md`` -- precision / recall / F1 / ROC-AUC /
PR-AUC / confusion matrix / feature importances / worst misclassifications.

Usage:
    python -m ml.evaluate
"""
from __future__ import annotations

import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.phishing_features import URL_FEATURE_NAMES  # noqa: E402

HERE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(HERE, "..", "app", "models", "phishing_model.pkl")
TEST_CSV = os.path.join(HERE, "dataset", "test.csv")
OOD_CSV = os.path.join(HERE, "ood_checkset.csv")
REPORT_OUT = os.path.join(HERE, "metrics_report.md")


def _md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def main():
    if not os.path.exists(MODEL_PATH):
        sys.exit("No model found. Run: python -m ml.train_model")
    if not os.path.exists(TEST_CSV):
        sys.exit("No test split found. Run: python -m ml.train_model")

    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    feature_names = bundle.get("feature_names", URL_FEATURE_NAMES)

    test = pd.read_csv(TEST_CSV)
    X = test[feature_names].to_numpy(dtype=float)
    y = test["label"].to_numpy(dtype=int)

    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)

    metrics = {
        "precision": precision_score(y, pred),
        "recall": recall_score(y, pred),
        "f1": f1_score(y, pred),
        "roc_auc": roc_auc_score(y, proba),
        "pr_auc": average_precision_score(y, proba),
    }
    cm = confusion_matrix(y, pred)
    tn, fp, fn, tp = cm.ravel()

    # Threshold that yields >=0.98 precision (few false alarms), if reachable.
    prec, rec, thr = precision_recall_curve(y, proba)
    hi_prec_thr = None
    for p, r, t in zip(prec[:-1], rec[:-1], thr):
        if p >= 0.98:
            hi_prec_thr = (round(float(t), 3), round(float(p), 4), round(float(r), 4))
            break

    importances = sorted(
        zip(feature_names, model.feature_importances_), key=lambda x: -x[1]
    )

    ds = bundle.get("dataset", {})
    lines = []
    lines.append("# Phishing URL Classifier — Metrics Report\n")
    lines.append(f"- **Model:** {bundle.get('model_type')} "
                 f"({model.n_estimators} trees, max_depth={model.max_depth})")
    lines.append(f"- **Trained at:** {bundle.get('trained_at')}")
    lines.append(f"- **Dataset source:** {ds.get('source')}")
    lines.append(f"- **Total URLs:** {ds.get('n_total')}  "
                 f"(train {ds.get('n_train')} / test {ds.get('n_test')})")
    lines.append(f"- **Class balance (all):** {ds.get('class_balance')}  "
                 f"(1 = phishing, 0 = benign)")
    lines.append(f"- **Features:** {len(feature_names)} URL-lexical + typosquatting "
                 f"(WHOIS / SSL / DOM signals are applied as runtime rules, not model inputs)\n")

    lines.append("## Held-out test performance (threshold = 0.50)\n")
    lines.append(_md_table(
        ["Metric", "Value"],
        [["Precision", f"{metrics['precision']:.4f}"],
         ["Recall", f"{metrics['recall']:.4f}"],
         ["F1", f"{metrics['f1']:.4f}"],
         ["ROC-AUC", f"{metrics['roc_auc']:.4f}"],
         ["PR-AUC", f"{metrics['pr_auc']:.4f}"]],
    ))
    lines.append("")

    lines.append("## 5-fold CV on training split\n")
    cvm = bundle.get("cv_metrics", {})
    lines.append(_md_table(["Metric", "Value"], [[k, v] for k, v in cvm.items()]))
    lines.append("")

    lines.append("## Confusion matrix (test)\n")
    lines.append(_md_table(
        ["", "Pred benign", "Pred phishing"],
        [["Actual benign", tn, fp], ["Actual phishing", fn, tp]],
    ))
    lines.append("")
    lines.append(f"- False positives (benign flagged): **{fp}** "
                 f"({fp / max(tn + fp, 1):.2%} of benign)")
    lines.append(f"- False negatives (phishing missed): **{fn}** "
                 f"({fn / max(tp + fn, 1):.2%} of phishing)\n")

    if hi_prec_thr:
        lines.append(f"- To reach **≥0.98 precision**, raise the decision threshold to "
                     f"**{hi_prec_thr[0]}** → precision {hi_prec_thr[1]}, recall {hi_prec_thr[2]}.\n")

    lines.append("## Top 15 feature importances\n")
    lines.append(_md_table(
        ["Feature", "Importance"],
        [[f, f"{imp:.4f}"] for f, imp in importances[:15]],
    ))
    lines.append("")

    lines.append("## sklearn classification report\n```")
    lines.append(classification_report(y, pred, target_names=["benign", "phishing"]))
    lines.append("```")

    # Worst misclassifications for the report / viva.
    test = test.assign(proba=proba, pred=pred)
    fp_rows = test[(test.label == 0) & (test.pred == 1)].nlargest(10, "proba")
    fn_rows = test[(test.label == 1) & (test.pred == 0)].nsmallest(10, "proba")
    if "url" in test.columns:
        lines.append("\n## Sample false positives (benign, high score)\n")
        lines.append(_md_table(["URL", "score"],
                     [[u[:80], f"{p:.3f}"] for u, p in zip(fp_rows.url, fp_rows.proba)]) or "_none_")
        lines.append("\n## Sample false negatives (phishing, low score)\n")
        lines.append(_md_table(["URL", "score"],
                     [[u[:80], f"{p:.3f}"] for u, p in zip(fn_rows.url, fn_rows.proba)]) or "_none_")

    # ---- Out-of-distribution sanity check (hand-labelled modern examples) ----
    if os.path.exists(OOD_CSV):
        from ml.data_loader import build_feature_frame  # noqa

        ood = pd.read_csv(OOD_CSV)
        ofeat = build_feature_frame(ood[["url", "label"]])
        oX = ofeat[feature_names].to_numpy(dtype=float)
        oy = ofeat["label"].to_numpy(dtype=int)
        op = model.predict_proba(oX)[:, 1]
        opred = (op >= 0.5).astype(int)
        oacc = float((opred == oy).mean())

        # Full pipeline: model score + typosquat / keyword rules + reputation
        # prior (WHOIS/SSL disabled for determinism).
        from app.services.phishing_predictor import PHISHING_THRESHOLD, analyze_url

        sys_scores, sys_pred = [], []
        for u in ood["url"]:
            res = analyze_url(u, live_lookups=False)
            sys_scores.append(res["risk_score"])
            sys_pred.append(int(res["risk_score"] >= PHISHING_THRESHOLD))
        sys_pred = np.array(sys_pred)
        sacc = float((sys_pred == oy).mean())

        lines.append("\n## Out-of-distribution sanity check\n")
        lines.append(f"Hand-labelled set of {len(ood)} modern URLs (not from the "
                     f"training distribution).\n")
        lines.append(_md_table(
            ["", "Accuracy", "Recall (phishing)", "Precision"],
            [["Raw RF model (thr 0.5)", f"{oacc:.2%}",
              f"{recall_score(oy, opred):.2%}",
              f"{precision_score(oy, opred, zero_division=0):.2%}"],
             ["Full pipeline (model + rules + reputation)", f"{sacc:.2%}",
              f"{recall_score(oy, sys_pred):.2%}",
              f"{precision_score(oy, sys_pred, zero_division=0):.2%}"]],
        ))
        lines.append("")
        miss = ood.assign(score=sys_scores, pred=sys_pred)
        miss = miss[miss.pred != miss.label]
        if len(miss):
            lines.append(_md_table(
                ["URL", "true", "score", "note"],
                [[u[:70], ("phish" if t else "benign"), f"{s:.3f}", n]
                 for u, t, s, n in zip(miss.url, miss.label, miss.score, miss.note)],
            ))
        else:
            lines.append("_All hand-labelled examples classified correctly._")
        lines.append(
            "\n> **Caveats.**\n"
            "> - PhiUSIIL's benign URLs are 100% HTTPS homepage URLs of curated "
            "high-reputation sites; its phishing URLs are ~50% HTTP and often "
            "carry deep paths. Without correction a model just learns "
            "\"HTTP or has-a-path -> phishing\". We re-attach realistic "
            "paths / subdomains / schemes to the benign class before training "
            "(see `ml/data_loader.py::_augment_benign`), which is why the "
            "held-out numbers here (~0.96) are lower and more realistic than "
            "the ~0.999 you get training on raw PhiUSIIL.\n"
            "> - The OOD set is small (30) and hand-picked; treat it as a "
            "smoke test of the model + rule layer, not a benchmark.\n"
            "> - Live traffic performance will still be lower than the held-out "
            "test set. The runtime WHOIS / SSL / typosquat / reputation rules "
            "exist to close that gap."
        )

    with open(REPORT_OUT, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[evaluate] wrote {os.path.relpath(REPORT_OUT)}")
    print(f"[evaluate] precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
          f"f1={metrics['f1']:.4f} roc_auc={metrics['roc_auc']:.4f}")


if __name__ == "__main__":
    main()
