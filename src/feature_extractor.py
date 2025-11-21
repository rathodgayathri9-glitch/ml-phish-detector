import re
import tldextract
from urllib.parse import urlparse
import numpy as np

# -----------------------------
# Helper Functions
# -----------------------------

def get_domain(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.domain + "." + ext.suffix
        return domain.lower()
    except:
        return ""

def get_hostname(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

# -----------------------------
# Feature Functions - v2
# -----------------------------

def url_length(url):
    return len(url)

def domain_length(url):
    domain = get_domain(url)
    return len(domain)

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def has_ip(url):
    host = get_hostname(url)
    return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0

def uses_https(url):
    return 1 if url.lower().startswith("https://") else 0

def suspicious_keywords(url):
    keywords = ["secure", "update", "confirm", "account", "banking", "verify", "login"]
    return sum(1 for w in keywords if w in url.lower())

def count_special_characters(url):
    special = re.findall(r"[@#%&*=?$+]", url)
    return len(special)

def path_length(url):
    try:
        return len(urlparse(url).path)
    except:
        return 0

def query_length(url):
    try:
        return len(urlparse(url).query)
    except:
        return 0

def digit_count(url):
    return sum(c.isdigit() for c in url)

# -----------------------------
# Feature Dictionary
# -----------------------------

def extract_features(url):
    return {
        "url_length": url_length(url),
        "domain_length": domain_length(url),
        "dot_count": count_dots(url),
        "hyphen_count": count_hyphens(url),
        "has_ip": has_ip(url),
        "https_used": uses_https(url),
        "suspicious_keywords": suspicious_keywords(url),
        "special_char_count": count_special_characters(url),
        "path_length": path_length(url),
        "query_length": query_length(url),
        "digit_count": digit_count(url),
    }

if __name__ == "__main__":
    test = "https://secure-login.bank.com/verify?id=88373"
    print(extract_features(test))
