# Phishing URL Classifier — Metrics Report

- **Model:** RandomForestClassifier (200 trees, max_depth=24)
- **Trained at:** 2026-10-25T10:11:56.539306Z
- **Dataset source:** UCI PhiUSIIL Phishing URL Dataset (id=967) + benign path/scheme augmentation
- **Total URLs:** 200000  (train 160000 / test 40000)
- **Class balance (all):** {1: 100000, 0: 100000}  (1 = phishing, 0 = benign)
- **Features:** 35 URL-lexical + typosquatting (WHOIS / SSL / DOM signals are applied as runtime rules, not model inputs)

## Held-out test performance (threshold = 0.50)

| Metric | Value |
| --- | --- |
| Precision | 0.9626 |
| Recall | 0.9558 |
| F1 | 0.9592 |
| ROC-AUC | 0.9897 |
| PR-AUC | 0.9899 |

## 5-fold CV on training split

| Metric | Value |
| --- | --- |
| precision | 0.9643 |
| recall | 0.9537 |
| f1 | 0.959 |
| roc_auc | 0.9894 |
| pr_auc | 0.9898 |

## Confusion matrix (test)

|  | Pred benign | Pred phishing |
| --- | --- | --- |
| Actual benign | 19257 | 743 |
| Actual phishing | 884 | 19116 |

- False positives (benign flagged): **743** (3.72% of benign)
- False negatives (phishing missed): **884** (4.42% of phishing)

- To reach **≥0.98 precision**, raise the decision threshold to **0.819** → precision 0.98, recall 0.8686.

## Top 15 feature importances

| Feature | Importance |
| --- | --- |
| has_https | 0.1702 |
| path_length | 0.1620 |
| subdomain_length | 0.1502 |
| url_length | 0.0673 |
| num_digits | 0.0531 |
| num_slashes | 0.0467 |
| host_entropy | 0.0397 |
| hostname_length | 0.0390 |
| digit_ratio | 0.0337 |
| non_alnum_ratio | 0.0289 |
| num_hyphens | 0.0277 |
| sld_length | 0.0247 |
| num_subdomains | 0.0247 |
| num_dots | 0.0239 |
| letter_ratio | 0.0224 |

## sklearn classification report
```
              precision    recall  f1-score   support

      benign       0.96      0.96      0.96     20000
    phishing       0.96      0.96      0.96     20000

    accuracy                           0.96     40000
   macro avg       0.96      0.96      0.96     40000
weighted avg       0.96      0.96      0.96     40000

```

## Sample false positives (benign, high score)

| URL | score |
| --- | --- |
| http://www.calit2.net | 0.983 |
| http://www.salon24.pl | 0.980 |
| https://liberalarts.utexas.edu/ | 0.979 |
| http://www.peta2.com | 0.979 |
| http://app.historicalcharts.noaa.gov | 0.976 |
| http://shop.studii.crifst.ro | 0.971 |
| http://store.dashboard.key2insight.com | 0.970 |
| http://www.vtd.uscourts.gov | 0.967 |
| http://www.inneres.bremen.de | 0.966 |
| http://auth.auth.soane.org | 0.964 |

## Sample false negatives (phishing, low score)

| URL | score |
| --- | --- |
| https://urls.sdbudimurni.com/uluwwxk | 0.009 |
| https://www.daisyfawcettceramics.com/wppp | 0.010 |
| https://help.emerrge.com/support/psd | 0.013 |
| https://kcck.knockoutdeportemarcial.com/kbb | 0.018 |
| https://jiangmatt.com | 0.024 |
| https://velgaming.com | 0.024 |
| https://nelsonra.co | 0.025 |
| https://hlperfaturaltauboleto.com | 0.026 |
| https://appatualizado.com | 0.027 |
| https://webmainnetrestore.com/wallets | 0.027 |

## Out-of-distribution sanity check

Hand-labelled set of 30 modern URLs (not from the training distribution).

|  | Accuracy | Recall (phishing) | Precision |
| --- | --- | --- | --- |
| Raw RF model (thr 0.5) | 80.00% | 94.44% | 77.27% |
| Full pipeline (model + rules + reputation) | 100.00% | 100.00% | 100.00% |

_All hand-labelled examples classified correctly._

> **Caveats.**
> - PhiUSIIL's benign URLs are 100% HTTPS homepage URLs of curated high-reputation sites; its phishing URLs are ~50% HTTP and often carry deep paths. Without correction a model just learns "HTTP or has-a-path -> phishing". We re-attach realistic paths / subdomains / schemes to the benign class before training (see `ml/data_loader.py::_augment_benign`), which is why the held-out numbers here (~0.96) are lower and more realistic than the ~0.999 you get training on raw PhiUSIIL.
> - The OOD set is small (30) and hand-picked; treat it as a smoke test of the model + rule layer, not a benchmark.
> - Live traffic performance will still be lower than the held-out test set. The runtime WHOIS / SSL / typosquat / reputation rules exist to close that gap.
