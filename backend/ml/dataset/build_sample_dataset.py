"""Generate a bundled fallback dataset of labelled URLs.

This is a *synthetic* dataset used only when the real UCI PhiUSIIL dataset
cannot be downloaded (offline grading, CI). It is constructed from:

  * benign  : real high-reputation domains with realistic paths
  * phishing: the same brands attacked with the classic tricks
              (typosquats, IP hosts, '@' tricks, deep subdomains,
               abused TLDs, credential keywords, punycode)

Document in the README that metrics on this fallback are optimistic --
the real dataset is the one that should be cited.
"""
from __future__ import annotations

import csv
import os
import random

random.seed(1337)

HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "sample_urls.csv")

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "reddit.com", "instagram.com", "linkedin.com", "netflix.com", "microsoft.com",
    "apple.com", "github.com", "stackoverflow.com", "paypal.com", "dropbox.com",
    "adobe.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "nytimes.com", "bbc.co.uk", "cnn.com", "theguardian.com", "medium.com",
    "spotify.com", "zoom.us", "slack.com", "coinbase.com", "cloudflare.com",
    "mozilla.org", "python.org", "wordpress.org", "shopify.com", "ebay.com",
    "walmart.com", "target.com", "fedex.com", "ups.com", "dhl.com",
]

BENIGN_PATHS = [
    "/", "/login", "/account/settings", "/help/faq", "/products/12345",
    "/blog/2026/01/security-tips", "/search?q=phishing+prevention",
    "/support/contact", "/pricing", "/about", "/us/en/home", "/watch?v=dQw4w9",
    "/user/profile", "/checkout/cart", "/api/v2/status",
]

BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank", "coinbase", "binance",
    "dhl", "fedex", "usps", "linkedin", "dropbox", "adobe", "instagram",
]

TYPO_TRICKS = [
    lambda b: b.replace("a", "4", 1) if "a" in b else b + "s",
    lambda b: b.replace("l", "1"),
    lambda b: b.replace("o", "0", 1) if "o" in b else b + "-inc",
    lambda b: b + "-" + random.choice(["secure", "login", "verify", "support"]),
    lambda b: random.choice(["secure-", "login-", "my-", "account-"]) + b,
    lambda b: b[:-1] + b[-1] + b[-1],
    lambda b: b.replace("i", "l") if "i" in b else "www-" + b,
]

BAD_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "work"]
KEYWORDS = ["login", "verify", "secure", "account-update", "confirm-identity",
            "webscr", "signin", "unlock-account", "billing-update"]
IPS = ["185.234.219.12", "45.129.33.7", "192.3.204.88", "23.94.11.240", "5.188.206.19"]


def benign_rows(n):
    rows = []
    for _ in range(n):
        d = random.choice(BENIGN_DOMAINS)
        p = random.choice(BENIGN_PATHS)
        sub = random.choice(["", "", "", "www.", "m.", "support.", "login.", "shop."])
        rows.append((f"https://{sub}{d}{p}", 0))
    return rows


def phishing_rows(n):
    rows = []
    for _ in range(n):
        b = random.choice(BRANDS)
        kind = random.randint(0, 6)
        kw = random.choice(KEYWORDS)
        if kind == 0:  # typosquat domain
            trick = random.choice(TYPO_TRICKS)
            dom = trick(b) + "." + random.choice(BAD_TLDS + ["com", "net"])
            url = f"http://{dom}/{kw}"
        elif kind == 1:  # brand in deep subdomain of junk domain
            junk = "".join(random.choices("abcdefghjkmnp", k=random.randint(8, 14)))
            url = f"http://{b}.{kw}.{junk}.{random.choice(BAD_TLDS)}/session"
        elif kind == 2:  # IP host
            url = f"http://{random.choice(IPS)}/{b}/{kw}.php"
        elif kind == 3:  # @ trick
            junk = "".join(random.choices("abcdefghjkmnp", k=10))
            url = f"http://{b}.com@{junk}.{random.choice(BAD_TLDS)}/{kw}"
        elif kind == 4:  # punycode homograph
            url = f"http://xn--{b}-9db.com/{kw}"
        elif kind == 5:  # very long credential-stuffed URL
            pad = "-".join(random.choices(KEYWORDS, k=4))
            url = (f"http://{b}-{kw}.{random.choice(BAD_TLDS)}/"
                   f"{pad}/{b}/webscr?cmd=_login&dispatch={'x'*40}")
        else:  # hyphenated lookalike with https
            dom = f"{b}-{random.choice(['secure','account','support','verify'])}-{random.choice(['login','id','auth'])}.com"
            url = f"https://{dom}/{kw}?ref={b}"
        rows.append((url, 1))
    return rows


def main():
    rows = benign_rows(1200) + phishing_rows(1200)
    random.shuffle(rows)
    with open(OUT, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])  # label: 1 = phishing, 0 = benign
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {OUT}")


if __name__ == "__main__":
    main()
