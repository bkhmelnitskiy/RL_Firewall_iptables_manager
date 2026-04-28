import argparse
import re
from pathlib import Path
from urllib.parse import unquote_to_bytes
from xml.etree import ElementTree as ET

import pandas as pd


# Attacker-crafted requests can embed literal spaces inside the URI
# (e.g. /?<meta http-equiv=set-cookie content="...">). A naive
# split(" ", 2) truncates the URI at the first space and drops the
# attack payload. Match the "METHOD <URI> HTTP/x.y" shape with a
# regex so URI keeps its spaces.
_REQUEST_LINE_RE = re.compile(r"^(\S+)\s+(.*?)\s+HTTP/\d[\d.]*\s*$", re.DOTALL)


# --- V2 attack-surface extractor (URI + body, URL-decoded, lowercased) ---
def extract_attack_surface(raw: bytes, max_decode_rounds: int = 3) -> bytes:
    """
    Strip HTTP-envelope entirely — keep only the attack surface:
      URI (path + query) + body
    URL-decode recursively (handles double-encoded payloads like %2527 → %27 → ').
    Lowercase at the end (attackers evade via mixed case).
    """
    text = raw.decode("latin-1", errors="replace")

    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    else:
        head, body = text, ""

    lines = head.split("\r\n")
    request_line = lines[0] if lines else ""

    m = _REQUEST_LINE_RE.match(request_line)
    if m:
        uri = m.group(2)
    else:
        parts = request_line.split(" ", 1)
        uri = parts[1] if len(parts) >= 2 else ""

    combined = uri
    if body:
        combined = combined + "\n" + body

    data = combined.encode("latin-1", errors="replace")
    for _ in range(max_decode_rounds):
        decoded = unquote_to_bytes(data)
        if decoded == data:
            break
        data = decoded

    return data.lower()


# --- Normalization (strip dataset-specific artifacts) ---
# Keep only these headers (attack detection signal). Everything else is dropped.
KEEP_HEADERS = {"content-type", "content-length", "referer"}

# Strip common web extensions from URI path. This removes the `.jsp` (CSIC)
# vs `.gif`/`.php4`/`.cfm` (ECML) artifact the model was latching onto.
EXT_RE = re.compile(
    r"\.(jsp|html?|gif|jpe?g|png|bmp|css|js|json|xml|pdf|doc|docx|xls|xlsx"
    r"|php[0-9]?|asp|aspx|cfm|cgi|pl|py|rb|sh|exe|bin|zip|tar|gz|msf|ico"
    r"|svg|woff|woff2|ttf|eot|mp3|mp4|avi|mov|txt|log|bak|tmp)"
    r"(?=(?:\?|;|/|\s|$))",
    re.IGNORECASE,
)


def normalize_http(raw: bytes) -> bytes:
    try:
        text = raw.decode("latin-1")
    except Exception:
        return raw

    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    else:
        head, body = text, ""

    lines = head.split("\r\n")
    if not lines:
        return raw

    request_line = lines[0]
    header_lines = lines[1:]

    parts = request_line.split(" ", 2)
    if len(parts) == 3:
        method, uri, protocol = parts
        if "?" in uri:
            path, qs = uri.split("?", 1)
        else:
            path, qs = uri, None
        path = EXT_RE.sub("", path)
        uri  = path + (f"?{qs}" if qs is not None else "")
        request_line = f"{method} {uri} {protocol}"

    kept = []
    for h in header_lines:
        if ":" not in h:
            continue
        key = h.split(":", 1)[0].strip().lower()
        if key in KEEP_HEADERS:
            kept.append(h)

    out = [request_line, *kept, ""]
    if body:
        out.append(body)
    return "\r\n".join(out).encode("latin-1", errors="replace")


CSIC_DIR_DEFAULT  = "web-application-attacks-datasets-master/csic_2010/dataset_cisc_train_test"
ECML_PATH_DEFAULT = "web-application-attacks-datasets-master/ecml_pkdd/learning_dataset.xml"
OUT_DIR_DEFAULT   = "artifacts/datasets"

ECML_NS = "http://www.example.org/ECMLPKDD"

ECML_LABEL_MAP = {
    "Valid":           "benign",
    "SqlInjection":    "sqli",
    "XSS":             "xss",
    "LdapInjection":   "ldap_injection",
    "XPathInjection":  "xpath_injection",
    "OsCommanding":    "cmd_injection",
    "PathTransversal": "path_traversal",
    "SSI":             "ssi",
}

# Strip absolute URL in CSIC request line (http://host:port) → wire format
CSIC_ABS_URL_RE = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) +http://[^ /]+")
# CSIC uses literal "null" as empty-body marker
CSIC_NULL_BODY_RE = re.compile(r"\n\s*null\s*$")


def parse_csic_file(path: Path, label: str, split: str) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"Start - Id: \d+\s*\n", text)
    records: list[dict] = []

    for blk in blocks:
        blk = blk.strip()
        if not blk:
            continue
        blk = re.sub(r"\nEnd - Id: \d+\s*$", "", blk).strip()

        lines = blk.split("\n", 1)
        if len(lines) < 2 or not lines[0].startswith("class:"):
            continue
        http_part = lines[1]

        http_part = CSIC_NULL_BODY_RE.sub("\n", http_part)

        raw = http_part.encode("utf-8", errors="replace")
        raw = CSIC_ABS_URL_RE.sub(lambda m: m.group(1) + b" ", raw, count=1)
        raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

        records.append({
            "payload": raw,
            "label":   label,
            "source":  "csic",
            "split":   split,
        })

    return records


def parse_ecml(path: Path) -> list[dict]:
    records: list[dict] = []

    for _, elem in ET.iterparse(str(path), events=("end",)):
        tag = elem.tag.split("}", 1)[-1]
        if tag != "sample":
            continue

        cls_type = elem.find(f"{{{ECML_NS}}}class/{{{ECML_NS}}}type")
        if cls_type is None or cls_type.text is None:
            elem.clear()
            continue
        label = ECML_LABEL_MAP.get(cls_type.text.strip())
        if label is None:
            elem.clear()
            continue

        req = elem.find(f"{{{ECML_NS}}}request")
        if req is None:
            elem.clear()
            continue

        def field(name: str, default: str = "") -> str:
            e = req.find(f"{{{ECML_NS}}}{name}")
            return (e.text if (e is not None and e.text is not None) else default)

        method   = field("method",   "GET").strip()       or "GET"
        protocol = field("protocol", "HTTP/1.1").strip()  or "HTTP/1.1"
        uri      = field("uri",      "/").strip()         or "/"
        query    = field("query",    "").strip()
        headers  = field("headers",  "").strip()
        body     = field("body",     "")

        full_uri = uri + (f"?{query}" if query else "")
        request_line = f"{method} {full_uri} {protocol}"

        parts = [request_line]
        if headers:
            parts.append(headers)
        parts.append("")
        if body:
            parts.append(body)

        raw_text = "\r\n".join(parts)
        raw = raw_text.encode("utf-8", errors="replace")
        raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")

        records.append({
            "payload": raw,
            "label":   label,
            "source":  "ecml",
            "split":   "all",
        })
        elem.clear()

    return records


def print_breakdown(df: pd.DataFrame, group_cols: list[str]) -> None:
    for key, grp in df.groupby(group_cols):
        key_str = " / ".join(str(k) for k in (key if isinstance(key, tuple) else (key,)))
        print(f"    {key_str:<30} {len(grp):>7,}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess CSIC 2010 and ECML/PKDD 2007 HTTP datasets")
    parser.add_argument("--csic-dir",  default=CSIC_DIR_DEFAULT)
    parser.add_argument("--ecml-path", default=ECML_PATH_DEFAULT)
    parser.add_argument("--out-dir",   default=OUT_DIR_DEFAULT)
    args = parser.parse_args()

    csic_dir  = Path(args.csic_dir)
    ecml_path = Path(args.ecml_path)
    out_dir   = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Parsing CSIC 2010 from: {csic_dir}")
    csic_records: list[dict] = []
    csic_records += parse_csic_file(csic_dir / "cisc_normalTraffic_train.txt",  "benign",     "train")
    csic_records += parse_csic_file(csic_dir / "cisc_normalTraffic_test.txt",   "benign",     "test")
    csic_records += parse_csic_file(csic_dir / "cisc_anomalousTraffic_test.txt","web_attack", "test")
    csic_df = pd.DataFrame(csic_records)
    print(f"  CSIC total: {len(csic_df):,}")
    print_breakdown(csic_df, ["label", "split"])

    print(f"\nParsing ECML/PKDD 2007 from: {ecml_path}")
    ecml_records = parse_ecml(ecml_path)
    ecml_df = pd.DataFrame(ecml_records)
    print(f"  ECML total: {len(ecml_df):,}")
    print_breakdown(ecml_df, ["label"])

    out_csic = out_dir / "http_payloads_csic.pkl"
    out_ecml = out_dir / "http_payloads_ecml.pkl"
    csic_df.to_pickle(out_csic)
    ecml_df.to_pickle(out_ecml)
    print(f"\nSaved {out_csic} ({out_csic.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {out_ecml} ({out_ecml.stat().st_size / 1e6:.1f} MB)")

    print("\nApplying normalization (strip dataset-specific artifacts) ...")
    csic_df_n = csic_df.copy()
    ecml_df_n = ecml_df.copy()
    csic_df_n["payload"] = csic_df_n["payload"].map(normalize_http)
    ecml_df_n["payload"] = ecml_df_n["payload"].map(normalize_http)

    out_csic_n = out_dir / "http_payloads_csic_normalized.pkl"
    out_ecml_n = out_dir / "http_payloads_ecml_normalized.pkl"
    csic_df_n.to_pickle(out_csic_n)
    ecml_df_n.to_pickle(out_ecml_n)
    print(f"Saved {out_csic_n} ({out_csic_n.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {out_ecml_n} ({out_ecml_n.stat().st_size / 1e6:.1f} MB)")

    print("\nApplying V2 attack-surface extraction (URI+body, URL-decoded, lowercase) ...")
    csic_df_d = csic_df.copy()
    ecml_df_d = ecml_df.copy()
    csic_df_d["payload"] = csic_df_d["payload"].map(extract_attack_surface)
    ecml_df_d["payload"] = ecml_df_d["payload"].map(extract_attack_surface)

    out_csic_d = out_dir / "http_payloads_csic_decoded.pkl"
    out_ecml_d = out_dir / "http_payloads_ecml_decoded.pkl"
    csic_df_d.to_pickle(out_csic_d)
    ecml_df_d.to_pickle(out_ecml_d)
    print(f"Saved {out_csic_d} ({out_csic_d.stat().st_size / 1e6:.1f} MB)")
    print(f"Saved {out_ecml_d} ({out_ecml_d.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
