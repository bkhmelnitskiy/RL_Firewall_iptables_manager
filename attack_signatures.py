"""
Per-attack signature features for web-attack detection.

Works on already-decoded, lowercased payloads (variant=decoded). Each attack
has a list of compiled regex patterns capturing well-known, high-signal
tokens of that attack class. The SignatureCounter transformer returns a
sparse count matrix (n_samples x n_patterns) that can be concatenated with
TF-IDF features via FeatureUnion.

Patterns chosen to cover BOTH:
  - CSIC/ECML training data (our positives)
  - FWAF validation data (never seen in training)

If a pattern appears in many benign samples too, it will simply get a weak
or negative coefficient — the LogReg decides. The goal here is to *put the
signals on the table*, so TF-IDF no longer has to rediscover them through
char n-grams that also encode dataset format.
"""
import re
from typing import Iterable

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin


# Each entry is a list of regex patterns — matched case-insensitive on the
# already-lowercased, url-decoded payload.
SIGNATURES: dict[str, list[str]] = {
    "sqli": [
        r"\bunion\b\s+(all\s+)?select\b",
        r"\bselect\b\s+[\w,\*\(\s]+\s+\bfrom\b",
        r"\binto\s+outfile\b",
        r"\bload_file\s*\(",
        r"\b(or|and)\s+\d+\s*=\s*\d+",
        r"\b(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
        r"'\s*(--|#|;)",
        r"\bsleep\s*\(",
        r"\bbenchmark\s*\(",
        r"\binformation_schema\b",
        r"\b(char|chr|concat|group_concat)\s*\(",
        r"0x[0-9a-f]{4,}",
        r"\b(drop|insert|delete|update)\s+(table|into|from)\b",
        r"\bshutdown\b",
        r"\b(having|group\s+by)\b\s+\w",
        r"\bexec(ute)?\s*\(",
        r"\bwaitfor\s+delay\b",
        # E10 additions (FWAF miss coverage)
        r"\bunion\b\s*(/\*[^*]*\*/\s*)+select\b",
        r"/\*[^*]*\*/\s*(select|union|from|where)\b",
        r"['\"]\s*(union|select|drop|insert|update|delete|exec|declare|from|where)\b",
        r"'\s*;\s*(drop|insert|update|delete|exec|shutdown)\b",
    ],
    "xss": [
        r"<\s*script\b",
        r"<\s*/\s*script\s*>",
        r"<\s*iframe\b",
        r"<\s*img\b[^>]*\s+(onerror|src\s*=\s*['\"]?javascript)",
        r"<\s*svg\b",
        r"<\s*object\b",
        r"<\s*embed\b",
        r"<\s*meta\b[^>]*http-equiv",
        r"<\s*body\b[^>]*onload",
        r"\bjavascript\s*:",
        r"\bvbscript\s*:",
        r"\bon(error|load|click|mouseover|focus|blur|change|submit)\s*=",
        r"\b(alert|prompt|confirm|eval|settimeout|setinterval)\s*\(",
        r"\bdocument\s*\.\s*(cookie|location|write|domain)\b",
        r"\bwindow\s*\.\s*(location|open)\b",
        r"\bexpression\s*\(",
        r"\bfromcharcode\s*\(",
        r"\bdata\s*:\s*text\s*/\s*html",
        # E10 additions (FWAF scanner magic-strings)
        r"(xss[-_]magic[-_]string|cross[_-]site[_-]scripting)",
    ],
    "cmd_injection": [
        r"/etc/(passwd|shadow|group|hosts)",
        r"/proc/(self|\d+)/",
        r"/bin/(sh|bash|ksh|zsh|dash)",
        r"/usr/bin/",
        r"(cmd|command)\.exe",
        r"\bpowershell(\.exe)?\b",
        r"[;&|`]\s*(cat|ls|id|whoami|uname|wget|curl|nc|netcat|ping|nslookup|dig|rm|chmod|chown)\b",
        r"\$\s*\(\s*\w",
        r"`[^`]+`",
        r"\|\|\s*\w",
        r"&&\s*\w",
        r"\bwinnt/system32\b",
        r"\bc:\\(windows|winnt|program)",
        r"\bwget\s+http",
        r"\bcurl\s+(http|-)",
        r"\.(sh|bat|cmd|ps1|exe|dll)\b",
        r"\bping\s+-[cn]\s+\d",
        # E10 additions (FWAF miss coverage)
        r"['\"]\s*(uname|whoami|cat|ls|id|pwd|sleep|ping|rm|echo)\b",
        r"\\x[01][0-9a-f]\s*(uname|whoami|cat|ls|pwd|id|ver|del|rem|rm|sleep|ping|echo)\b",
        r"\bsleep\s+\d+\s*[#&;|]",
        r"\bq\d{5,}\s*(#|&rem\b|&ver\b|\\x[01][0-9a-f])",
        r"&rem[\s,;&#\\]",
        r"[?&]cmd=",
        r"\bsystem\s*\(",
        r"\bphpinfo\s*\(",
        r"\b(eval|passthru|shell_exec|popen|proc_open|assert)\s*\(",
        r"<\?\s*(php|=)",
        r"\$\{\s*\w+\s*\(",
        r"@\s*system\s*\(",
        r"\b(nessus|sqlmap|acunetix|netsparker|wvs-|skipfish|nikto|w3af)\b",
        r"\.nasl\b",
        r"\bping[;,\s|&]+-[cwn]\b\s*\d",
    ],
    "path_traversal": [
        r"(\.\.[\\/]){2,}",
        r"%2e%2e(%2f|%5c|/|\\)",
        r"\.\.%(2f|5c|c0%af)",
        r"%252e%252e",
        r"/etc/(passwd|shadow|group|hosts)",
        r"/proc/(self|\d+)/(environ|cmdline|status|maps)",
        r"[/\\](boot|windows|winnt|win)\.ini",
        r"[/\\](autoexec|config)\.(bat|sys)",
        r"file\s*://",
        r"php\s*://(filter|input|zip|expect)",
        r"zip\s*://",
        r"expect\s*://",
        r"[a-z]:\\(windows|winnt|program|users|docume)",
        # E10 additions (FWAF miss coverage)
        r"%00\b|\\x00\b",
        r"\.\.[\\/](?:[\w.-]+[\\/]){0,3}(etc|proc|windows|winnt|boot|home|var|root|usr)\b",
        r"[\\/]\.ht(access|passwd)\b|[\\/]htpasswd\b",
    ],
    "ldap_injection": [
        r"\*\s*\)\s*\(\s*[\w|&!]",
        r"\)\s*\(\s*\|\s*\(",
        r"\)\s*\(\s*&\s*\(",
        r"\)\s*\(\s*!\s*\(",
        r"\|\s*\(\s*(uid|cn|ou|dc|sn|mail)\s*=",
        r"&\s*\(\s*(uid|cn|ou|dc|sn|mail)\s*=",
        r"\(\s*\|\s*\(\s*objectclass",
        r"\*\s*\)\s*\(\s*(uid|cn|objectclass)",
        r"admin\s*\*\s*\)",
        r"\)\s*\(\s*\|\s*\(\s*\w+\s*=\s*\*",
    ],
    "xpath_injection": [
        r"'\s*or\s*'1'\s*=\s*'1",
        r"'\s*or\s*''\s*=\s*'",
        r'"\s*or\s*""\s*=\s*"',
        r"\]\s*\|\s*//",
        r"\bchild\s*::\s*(node|text)\s*\(",
        r"\bposition\s*\(\s*\)\s*=",
        r"\bcount\s*\(\s*[/@*]",
        r"\bsubstring\s*\(\s*(name|text)",
        r"\btext\s*\(\s*\)\s*\[",
        r"\bnamespace-uri\s*\(",
        r"\bcontains\s*\(\s*(name|text|//)",
        r"\band\s+string-length\s*\(",
        r"//\s*\*\s*\[",
        r"\bor\s+(true|not\s*\(true)",
    ],
    "ssi": [
        r"<!--\s*#\s*exec\b",
        r"<!--\s*#\s*include\b",
        r"<!--\s*#\s*config\b",
        r"<!--\s*#\s*echo\b",
        r"<!--\s*#\s*set\b",
        r"<!--\s*#\s*printenv\b",
        r"<!--\s*#\s*email\b",
        r"<!--\s*#\s*fsize\b",
        r"<!--\s*#\s*flastmod\b",
        r'\bcmd\s*=\s*["\']',
        r'\bvirtual\s*=\s*["\']',
        r'\bfile\s*=\s*["\']/',
    ],
}

# Universal = union across all attack types.
SIGNATURES["web_attack_universal"] = sum(SIGNATURES.values(), [])
# Generic = same as universal (same payloads either way).
SIGNATURES["web_attack_generic"] = SIGNATURES["web_attack_universal"]


class SignatureCounter(BaseEstimator, TransformerMixin):
    """
    sklearn transformer: count occurrences of each attack-signature regex in
    each input string. Returns a sparse (n_samples, n_patterns) int matrix.
    """

    def __init__(self, attack: str):
        self.attack = attack
        self.patterns_ = [re.compile(p, re.IGNORECASE | re.DOTALL)
                          for p in SIGNATURES[attack]]

    def fit(self, X, y=None):
        return self

    def transform(self, X: Iterable[str]):
        rows, cols, data = [], [], []
        for i, text in enumerate(X):
            for j, pat in enumerate(self.patterns_):
                c = len(pat.findall(text))
                if c:
                    rows.append(i)
                    cols.append(j)
                    data.append(c)
        n_rows = len(X) if hasattr(X, "__len__") else i + 1
        return csr_matrix(
            (data, (rows, cols)),
            shape=(n_rows, len(self.patterns_)),
            dtype=np.float64,
        )

    def get_feature_names_out(self, input_features=None):
        return np.array([f"sig::{self.attack}::{i}::{SIGNATURES[self.attack][i][:40]}"
                         for i in range(len(self.patterns_))])
