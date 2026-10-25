"""Combine VirusTotal reputation, filename/MIME heuristics and the source-URL
phishing model into one download verdict."""
from __future__ import annotations

import hashlib
from typing import Optional

from . import file_heuristics
from .phishing_predictor import analyze_url
from .virustotal_client import VirusTotalClient, get_client

SUSPICIOUS_THRESHOLD = 0.35
MALICIOUS_THRESHOLD = 0.65

# The EICAR anti-virus test string is the only "malware" this project handles.
# Recognised locally so the pipeline is testable without VirusTotal.
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = hashlib.sha256(EICAR_STRING.encode("ascii")).hexdigest()


def _verdict(score: float) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "benign"


def _noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - w
    return 1.0 - p


def analyze_file(filename: str, sha256: Optional[str], size_bytes: Optional[int],
                 source_url: Optional[str], mime_type: Optional[str],
                 vt: Optional[VirusTotalClient] = None) -> dict:
    weights: list[float] = []
    scored: list[tuple[float, str]] = []
    notes: list[str] = []

    for w, why in file_heuristics.evaluate(filename, mime_type):
        weights.append(w)
        scored.append((w, why))
    heuristic_weights = list(weights)

    source = None
    if source_url:
        try:
            source = analyze_url(source_url, live_lookups=False)
        except Exception as exc:  # model missing or unparseable URL: heuristics still work
            notes.append(f"source URL not scored ({exc.__class__.__name__})")
        if source and source["verdict"] != "benign":
            w = 0.50 if source["verdict"] == "phishing" else 0.30
            weights.append(w)
            scored.append((w, f"Download source is rated {source['verdict']} "
                           f"({round(source['risk_score'] * 100)}% risk): {source['reasons'][0]}"))

    vt_result: dict
    if not sha256:
        vt_result = {"status": "not_checked", "detail": "no hash supplied (metadata-only scan)"}
    elif sha256.lower() == EICAR_SHA256:
        vt_result = {"status": "malicious", "malicious": 0, "engines": 0, "cached": False,
                     "threat_label": "EICAR-Test-File",
                     "detail": "matches the EICAR anti-virus test file (local signature)"}
        weights.append(0.95)
        scored.append((0.95, "Matches the EICAR anti-virus test file (harmless test signature)"))
    else:
        vt_result = (vt or get_client()).lookup(sha256)
        st = vt_result["status"]
        if st == "malicious":
            m = vt_result["malicious"]
            w = 0.95 if m >= 3 else 0.55
            weights.append(w)
            scored.append((w, f"VirusTotal: {m} of {vt_result['engines']} engines flag this file"
                           + (f" ({vt_result['threat_label']})" if vt_result.get("threat_label") else "")))
        elif st == "suspicious":
            weights.append(0.40)
            scored.append((0.40, f"VirusTotal: {vt_result['suspicious']} engine(s) rate this file suspicious"))
        elif st == "clean" and vt_result["engines"] >= 10:
            # Widely scanned and clean: heuristics about the *name* matter much less.
            scored.append((0.0, f"VirusTotal: no detections across {vt_result['engines']} engines"))
        elif st == "unknown":
            if any(w >= 0.15 for w in heuristic_weights):
                weights.append(0.10)
            scored.append((0.0, "Hash is unknown to VirusTotal (never seen; file was not uploaded)"))
        else:
            notes.append(f"VirusTotal {st}: {vt_result.get('detail', '')}")

    score = _noisy_or(weights)
    if vt_result["status"] == "clean" and vt_result.get("engines", 0) >= 10:
        score = min(score, 0.30)
    score = round(min(score, 1.0), 4)

    reasons = [why for _, why in sorted(scored, key=lambda x: -x[0])]
    if not reasons:
        reasons.append("No suspicious indicators found")
    return {
        "filename": file_heuristics.basename(filename),
        "sha256": sha256.lower() if sha256 else None,
        "risk_score": score,
        "verdict": _verdict(score),
        "reasons": reasons + notes,
        "virustotal": vt_result,
        "analysis_mode": "hash+metadata" if sha256 else "metadata_only",
        "source_url_verdict": source["verdict"] if source else None,
    }
