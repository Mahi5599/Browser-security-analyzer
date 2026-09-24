"""Curated list of frequently-impersonated brand domains.

Used for typosquatting / homograph detection via edit distance. Keep this list
small and high-value (banks, big tech, payments, shipping, crypto) so that an
edit-distance match is a strong signal rather than noise.
"""

# (registered domain, human label)
TOP_BRAND_DOMAINS = [
    ("paypal.com", "PayPal"),
    ("google.com", "Google"),
    ("gmail.com", "Gmail"),
    ("microsoft.com", "Microsoft"),
    ("office365.com", "Office 365"),
    ("outlook.com", "Outlook"),
    ("live.com", "Microsoft Live"),
    ("apple.com", "Apple"),
    ("icloud.com", "iCloud"),
    ("amazon.com", "Amazon"),
    ("aws.amazon.com", "AWS"),
    ("facebook.com", "Facebook"),
    ("instagram.com", "Instagram"),
    ("whatsapp.com", "WhatsApp"),
    ("netflix.com", "Netflix"),
    ("linkedin.com", "LinkedIn"),
    ("twitter.com", "Twitter/X"),
    ("x.com", "Twitter/X"),
    ("reddit.com", "Reddit"),
    ("tiktok.com", "TikTok"),
    ("snapchat.com", "Snapchat"),
    ("spotify.com", "Spotify"),
    ("steamcommunity.com", "Steam"),
    ("chase.com", "Chase Bank"),
    ("wellsfargo.com", "Wells Fargo"),
    ("bankofamerica.com", "Bank of America"),
    ("citibank.com", "Citibank"),
    ("citi.com", "Citi"),
    ("americanexpress.com", "American Express"),
    ("capitalone.com", "Capital One"),
    ("usbank.com", "U.S. Bank"),
    ("hsbc.com", "HSBC"),
    ("barclays.co.uk", "Barclays"),
    ("santander.com", "Santander"),
    ("lloydsbank.com", "Lloyds Bank"),
    ("dhl.com", "DHL"),
    ("fedex.com", "FedEx"),
    ("ups.com", "UPS"),
    ("usps.com", "USPS"),
    ("adobe.com", "Adobe"),
    ("dropbox.com", "Dropbox"),
    ("github.com", "GitHub"),
    ("yahoo.com", "Yahoo"),
    ("coinbase.com", "Coinbase"),
    ("binance.com", "Binance"),
    ("blockchain.com", "Blockchain.com"),
    ("metamask.io", "MetaMask"),
    ("ebay.com", "eBay"),
    ("walmart.com", "Walmart"),
    ("target.com", "Target"),
    ("alibaba.com", "Alibaba"),
    ("aliexpress.com", "AliExpress"),
    ("wetransfer.com", "WeTransfer"),
    ("docusign.com", "DocuSign"),
    ("zoom.us", "Zoom"),
    ("slack.com", "Slack"),
    ("stripe.com", "Stripe"),
]

# Just the second-level label (e.g. "paypal") -> brand name
BRAND_SLD = {}
for _domain, _label in TOP_BRAND_DOMAINS:
    _sld = _domain.split(".")[0]
    BRAND_SLD.setdefault(_sld, _label)

BRAND_DOMAIN_SET = {d for d, _ in TOP_BRAND_DOMAINS}

# Legitimate brand-adjacent domains that contain a brand token but are NOT
# impersonation -- keeps them out of the typosquat reason text.
LEGIT_BRAND_ADJACENT = {
    "googleapis.com", "googleusercontent.com", "gstatic.com", "google-analytics.com",
    "goo.gl", "youtube.com", "youtu.be", "android.com", "withgoogle.com",
    "microsoftonline.com", "microsoft.net", "msftconnecttest.com", "windows.net",
    "azureedge.net", "office.com", "office.net", "sharepoint.com", "live.net",
    "apple-cloudkit.com", "cdn-apple.com", "mzstatic.com",
    "paypalobjects.com", "paypal-communication.com",
    "amazonaws.com", "amazon-adsystem.com", "media-amazon.com", "ssl-images-amazon.com",
    "fbcdn.net", "facebook.net", "fb.com", "linkedin.cn",
    "adobe.io", "typekit.net", "adobedtm.com",
}
