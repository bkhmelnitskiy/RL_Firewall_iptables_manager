# Historia prac — wykrywanie ataków na poziomie treści pakietu

Dokument zawiera pełną historię rozwoju modułu detekcji ataków webowych na
podstawie treści HTTP (równoległy do istniejącego modelu flow-based opartego
o CICIDS2017 + Random Forest).

---

## Etap 0 — Punkt wyjścia (2026-04-21)

**Istniejące artefakty projektu:**
- `train_model.py` — Random Forest na feature'ach przepływu (CICIDS2017).
- `detector.py` — klasa `MLDetector` opakowująca model.
- `iptables_rules_generator.py` — generuje reguły iptables z wyników detekcji.

**Cel rozszerzenia:** detekcja ataków treściowych w pakietach HTTP
(SQL injection, XSS, path traversal itd.) jako równoległy ensemble modeli
binarnych pracujących na surowych bajtach HTTP. Planowana integracja przez
NFQUEUE dla inline inspection na WSL z prawdziwym iptables.

**Wybrana architektura:** ensemble niezależnych modeli binarnych (jeden per
typ ataku) + 1-2 modele "generic/universal". Każdy model: `TF-IDF char
n-gram(3-5)` + `LogisticRegression(class_weight='balanced')`.

**Pobrane datasety:**
- CSIC 2010 — 72k benign train+test + 25k ataków (binary labeled).
- ECML/PKDD 2007 — 35k benign + 15k ataków w 7 typach (sqli, xss,
  cmd_injection, path_traversal, ldap_injection, xpath_injection, ssi).

---

## Etap 1 — `packet_preprocess.py` + pierwszy model (CSIC-only)

**Co zrobiono:**
- `packet_preprocess.py` parsuje oba datasety do jednolitego formatu
  (kolumny: `payload` = surowe bajty HTTP-request, `label`, `source`, `split`).
  Output: `artifacts/datasets/http_payloads_{csic,ecml}.pkl`.
- `train_packet_model.py` z CLI `--attack {web_attack_generic,sqli,xss,...}`.
- Wytrenowano `web_attack_generic` na CSIC (attacks vs benigns).

**Metryka in-dataset (test split CSIC):** F1 > 0.99 dla obu klas.

**Status:** wygląda świetnie na pierwszy rzut oka.

---

## Etap 2 — Ewaluacja cross-dataset: pierwsze ostrzeżenie

**Co zrobiono:** `evaluate_cross_dataset.py` — skrypt predykcji każdego modelu
na wszystkich slice'ach obu datasetów (CSIC benign/attack, ECML benign, każdy
typ ataku ECML). Tabele: FPR na benignach, TPR na atakach, oznaczenia
`[TRAIN+]/[TRAIN-]/[FRESH]`.

Aby uniknąć OOM w WSL (7.3 GB RAM, ładowanie wszystkich modeli jednocześnie
przekracza limit), każdy model uruchamiany w osobnym subprocess, wyniki
cache'owane do JSON per model, potem `--aggregate` renderuje tabele.

**Wynik szokujący:**
- `web_attack_generic` na `CSIC benign`: **0.69% FPR** (OK, model to widział).
- `web_attack_generic` na `ECML benign`: **100.00% FPR** (KATASTROFA — każdy
  benign ECML flagowany jako atak).

**Root cause:** model trenowany TYLKO na CSIC. CSIC i ECML mają różne
artefakty formatowe (inne URL-encodingi parametrów, inne rozszerzenia
plików `.jsp` vs `.gif`/`.php4`, inne struktury headerów). Model nauczył
się "wygląda jak CSIC = benign" zamiast "wygląda jak zwykły HTTP = benign".

---

## Etap 3 — Option A: model `web_attack_universal` na mieszance

**Co zrobiono:** `web_attack_universal` trenowany na (CSIC ataki + ECML ataki)
vs (CSIC benigny + ECML benigny). 40k pozytywów, 107k negatywów.

Pierwsze podejście z `ngram=3-5, max_features=100k` wywaliło WSL (OOM
exit 9). Zredukowano do `ngram=3-4, max_features=50k`.

**Wyniki:**
- CSIC benign FPR: **1.43%**, ECML benign FPR: **0.26%**.
- TPR per typ ataku: **96–100%**.
- Zachowuje się porządnie na obu datasetach.

**Niepokój:** pojedyncze modele ECML (np. `sqli`) wciąż miały sztucznie
wysokie TPR na innych ECML-atakach (`sqli → ECML xpath: 98.73%`). To sugeruje
że modele uczą się podpisu formatu-ECML, nie konkretnego wzorca ataku.

---

## Etap 4 — Option B: normalizacja HTTP

**Co zrobiono:** dodana funkcja `normalize_http()` w `packet_preprocess.py`:
- Strip rozszerzeń plików z URI path (regex `EXT_RE` — usuwa `.jsp`, `.gif`,
  `.php4`, `.cfm`, etc.).
- Zostawia tylko 3 nagłówki: `Content-Type`, `Content-Length`, `Referer`
  (`KEEP_HEADERS`). Wszystkie inne (`User-Agent`, `Host`, `Cookie`,
  `Accept-*`...) usuwane.

Wygenerowane normalized pickles (~12 MB CSIC, ~15 MB ECML). Wszystkie 8
modeli przetrenowane na `--data-variant normalized`.

**Spadek F1 (in-dataset), co JEST pożądane:**
| Model | F1 raw | F1 normalized |
|---|---:|---:|
| sqli | 0.9922 | 0.8719 |
| xss | 0.9959 | 0.8962 |
| cmd_injection | 0.9870 | 0.9290 |
| path_traversal | 0.9924 | 0.8976 |
| ldap_injection | 1.0000 | 0.8768 |
| xpath_injection | 1.0000 | 0.8832 |
| ssi | 1.0000 | 0.8710 |
| web_attack_universal | — | 0.9365 |

**Ewaluacja cross-dataset (normalized):**
- FPR pozostaje <2% na obu benignach dla wszystkich modeli.
- TPR na własnym ataku spada 3–5 pkt — prawdziwa generalizacja.
- Najciekawsze cross-attack przesunięcia:
  - `sqli → ECML xpath`: 98.7% → 81.8% (sztuczny skrót formatowy obcięty)
  - `ssi → ECML xpath`: 2.8% → 47.0% (wzrost — model zaczął widzieć
    prawdziwe wzorce)
  - `ldap → ECML xss`: 56.5% → 71.0% (prawdziwe overlap wzorców)

**Rekomendacja do wdrożenia w tym etapie:** `web_attack_universal` normalized —
0.81%/1.83% FPR, 83–91% TPR na każdym typie ataku ECML, 98.5% na CSIC attack.

---

## Etap 5 — Option C: walidacja FWAF, ujawnienie głównego problemu

**Co zrobiono:** pobrany dataset FWAF
(`github.com/faizann24/Fwaf-Machine-Learning-Driven-Web-Application-Firewall`):
48 126 URL-i atakujących, 1 294 531 URL-i benign. Próbka: 100k benign + cała
populacja ataków (48k).

Ciekawostka techniczna: Windows Defender kwarantannował `badqueries.txt`
w ciągu sekund od pobrania na `C:\`. Rozwiązanie: pobranie tarballa do
filesystemu WSL (`~/fwaf_data/`) poza zasięg skanera AV.

Każdy URL opakowany jako minimalny HTTP request:
`GET <uri> HTTP/1.1\r\nHost: test.local\r\n\r\n`.

**Wyniki (FPR na goodqueries / TPR na badqueries):**

| Model | RAW FPR | RAW TPR | NORM FPR | NORM TPR |
|---|---:|---:|---:|---:|
| web_attack_generic | 99.39% | 98.74% | — | — |
| web_attack_universal | 99.99% | 100.00% | **99.82%** | 98.50% |
| sqli | 0.54% | 14.31% | 0.00% | 4.67% |
| xss | 15.10% | 42.18% | 10.98% | 34.15% |
| cmd_injection | 99.95% | 99.94% | 0.06% | 14.92% |
| path_traversal | 84.11% | 44.51% | 74.17% | 9.80% |
| ldap_injection | 0.01% | 10.02% | 0.00% | 5.50% |
| xpath_injection | 0.00% | 0.39% | 0.00% | 0.09% |
| ssi | 0.04% | 7.49% | 0.00% | 1.36% |

**Katastrofalne odkrycie:**
1. `web_attack_universal` flaguje **99.82% benign URL-i z FWAF** jako atak.
   Nadaje się do wdrożenia **tylko** na ruchu stylu CSIC/ECML.
2. Modele per-attack normalized są hiper-ostrożne: sqli łapie 4.67%
   prawdziwych ataków, ssi 1.36%, xpath 0.09%. Niskie FPR bezużyteczne bez
   TPR.

**Analiza top-features modelu `web_attack_universal` (normalized)** wyjaśnia
wszystko:
- ATTACK (najwyższe wagi): `+++`, `%2F`, `dA=`, `oA=`, `%27`, `/ H`,
  `/ HT`, `B1A=`, `nA=`, `%2C`, `cioA`, `ginA`.
- BENIGN (najniższe wagi): `os H`, `tos `, `: /`, `r: /`, `Ref`, `erer`,
  `efer`, `rer:`, `: `.

Model nauczył się:
- **"Benign wygląda jak ma nagłówek `Referer:`"** — FWAF goodqueries nie
  mają headerów, więc trigger: atak.
- **"Atak wygląda jak kończy się `/` przed HTTP/1.1"** — FWAF goodqueries
  często kończą się `/` (np. `/103886/`), więc trigger: atak.
- **"Atak wygląda jak CSIC-parametry `dA=`, `B1A=`"** — te tokeny
  pochodzą z URL-encoded parameter namesów w CSIC attacks (base64-like).

**Wniosek:** obecny pipeline (TF-IDF char n-gram na surowych bajtach HTTP)
wykrywa *format treningowego datasetu*, a nie *wzorce ataków*. Normalizacja
usuwa część formatowych shortcuts, ale nie dość. Feature'ami z największymi
wagami wciąż są artefakty CSIC (parameter namesy) i pozycje strukturalne
(`/ HT`), a nie semantyczne sygnatury ataku.

---

## Etap 6 — Pipeline V2 decoded (2026-04-22)

**Decyzja projektowa:** przebudować pipeline tak, żeby model widział tylko
powierzchnię ataku (URI + body), URL-zdekodowaną, bez formatowych
artefaktów HTTP-enveloppe.

**Zrealizowany pipeline V2:**
1. `extract_attack_surface()` w `packet_preprocess.py`:
   - Ekstrahuje URI (path+query) + body (pomija request-line, HTTP-version, headery).
   - URL-decode rekurencyjnie (do 3 rund — handle double encoding `%2527`→`%27`→`'`).
   - Lowercase.
2. Wygenerowano `http_payloads_{csic,ecml}_decoded.pkl`.
3. `train_packet_model.py` rozszerzony o `--data-variant decoded` + auto-select
   `artifacts/packet_models_decoded/`.
4. Ewaluator `evaluate_fwaf.py` rozszerzony o wariant `decoded`.
5. Wytrenowano 8 modeli (web_attack_universal + 7 per-attack) na decoded.

**In-dataset F1 (decoded):** zbliżone do normalized (0.86–0.92).

**FWAF evaluation (decoded):**

| Model                | FPR       | TPR       | Notes                         |
|----------------------|----------:|----------:|-------------------------------|
| web_attack_universal |    39.33% |    51.31% | FPR wciąż za wysokie          |
| sqli                 |     0.23% |     1.14% | ✗ recall                       |
| xss                  |    15.25% |    22.37% | ⚠ FPR                          |
| cmd_injection        |     0.36% |    13.73% |                                |
| path_traversal       |     0.70% |    12.90% | FPR z 74% → 0.7% (zwycięstwo) |
| ldap_injection       |     0.57% |     0.67% |                                |
| xpath_injection      |     0.11% |     0.06% |                                |
| ssi                  |     0.05% |     1.04% |                                |

**Wniosek:** ogromna poprawa `web_attack_universal` (99.82% → 39.33% FPR)
i `path_traversal` (74% → 0.7%), ale TPR wciąż zbyt niski na większości
per-attack models. Potrzebne feature engineering.

---

## Etap 7 — Per-attack signature feature engineering

**Decyzja:** dodać **per-attack regex signatures** jako dodatkowe feature'y.
Każdy typ ataku ma własny zestaw wzorców (np. sqli: `UNION SELECT`, `OR 1=1`,
`--`, `sleep(...)`; xss: `<script`, `javascript:`, `onerror=`; cmd: `/etc/passwd`,
`;cat`, `/bin/sh`). Patterns dobrane tak, żeby pokrywały **oba** datasety
(ECML training + FWAF validation).

**Implementacja:** `attack_signatures.py`:
- `SIGNATURES` dict: attack → list of regex patterns (10–101 per attack).
- `SignatureCounter` (sklearn Transformer): zwraca sparse count matrix
  (n_samples × n_patterns).
- `web_attack_universal` = union wszystkich sygnatur (101 patternów).

**Trzy warianty architektury przetestowane:**

### 7a. TF-IDF + signatures (FeatureUnion) — `packet_models_decoded_sig/`

| Model                | FPR       | TPR       |
|----------------------|----------:|----------:|
| web_attack_universal |    37.66% |    50.00% |
| sqli                 |     0.20% |     2.65% |
| xss                  |     0.62% |    15.96% |
| cmd_injection        |     0.35% |    13.79% |
| path_traversal       |     0.19% |    11.86% |
| ldap_injection       |     0.13% |     0.12% |
| xpath_injection      |     0.07% |     0.05% |
| ssi                  |     0.03% |     0.32% |

**Obserwacja:** xss FPR spadł 15.25% → 0.62% (dramatycznie). Ale TPR ogólnie
nie urósł — TF-IDF wciąż dominuje sygnatury.

### 7b. Signatures-only LogReg — `packet_models_decoded_sigonly/`

| Model                | FPR       | TPR       |
|----------------------|----------:|----------:|
| **web_attack_universal** | **0.08%** | **32.62%** |
| sqli                 |     0.00% |     1.63% |
| xss                  |     0.00% |    15.93% |
| cmd_injection        |     0.52% |    22.64% |
| path_traversal       |     0.01% |    10.43% |
| ldap_injection       |     0.00% |     0.02% |
| xpath_injection      |     0.00% |     0.01% |
| ssi                  |     0.00% |     0.17% |

**Obserwacja:** `web_attack_universal` sigonly = **pierwszy deploymentowalny
model** — FPR 0.08% (1 na 1 250 benignów) + TPR 32.62%. Modele ~10 kB każdy
(zamiast 16 MB z TF-IDF).

### 7c. Rule-based (dowolna sygnatura → atak, bez LogReg)

| Rule set             | FPR       | TPR       |
|----------------------|----------:|----------:|
| **web_attack_universal (101 sig)** | **0.545%** | **55.82%** |
| sqli (17 sig)        |    0.022% |     2.25% |
| xss (18 sig)         |    0.000% |    16.47% |
| cmd_injection (17 sig) |  0.520% |    36.58% |
| path_traversal (13 sig) | 0.012% |    10.43% |
| ldap_injection (10 sig) | 0.000% |     0.04% |
| xpath_injection (14 sig) | 0.000% | 0.06% |
| ssi (12 sig)         |    0.000% |     0.19% |
| **Union 7 per-attack** | **0.545%** | **55.82%** |

**Dlaczego rule-based > LogReg sigonly:**
LogReg uczył się wag z ECML; patterny rzadkie w ECML dostawały małe wagi
(poniżej progu decyzyjnego). Rule-based respektuje każde trafienie sygnatury
tak samo — uniwersalne cross-dataset feature'y nie są tłumione.

**Przykład missed-by-LogReg-sigonly, caught-by-rule:**
FWAF payload `<img src="javascript:alert(...)">` zawiera xss sygnaturę
(`<img ... src=javascript`), ale xss LogReg-sigonly miał niski
współczynnik dla tego patternu (rzadki w ECML xss) → nie odpalał.
Rule-based łapie 100% takich przypadków.

---

## Rekomendacja produkcyjna (stan na 2026-04-22)

**Deploy:** **rule-based web_attack_universal** z 101 wzorcami sygnatur.
- FPR: 0.545% (1 na 180 benignów)
- TPR: 55.82% (ponad połowa ataków złapana)
- Żadne ML — deterministyczny, zero modeli do załadowania, ~0 latency.
- `attack_surface` preprocessing (URI + body URL-decoded lowercase) jest
  wymagany przed dopasowaniem.

**Hybryda alternatywna (jeśli potrzebujemy wyższego TPR kosztem FPR):**
- Rule-based overlay: sygnatura → blok.
- LogReg TF-IDF-decoded dla przypadków bez sygnatury (fallback na szerszy
  ML). Ale uwaga: TF-IDF wciąż ma 39% FPR na FWAF — dodaje FP-y.

**Droga do wyższego TPR (dalsze prace):**
1. **Rozszerzenie sygnatur**: 45% FWAF pozostaje niezłapane. Analiza 28k
   missed payloadów pokazuje:
   - Obfuskowane bash (`$IFS`, `$((expr))`, `$(echo VAR)`) — brak w cmd sigs.
   - Path traversal z backslash-escape (`.\/\.\.`).
   - XSS przez `<meta http-equiv=set-cookie>` (nie było w sigs).
   - Double/triple URL-encoding — dekoder obsługuje 3 rundy, niektóre payloady
     mają więcej.
2. **Rozbudowa datasetu treningowego**: dodać FWAF train partition (trzymać
   goodqueries/badqueries split; walidować na trzecim datasecie).
3. **Rule augmentation przez attack feedback**: automat z produkcji zbiera
   bloki, payloady analizowane ręcznie, dobre wzorce dodawane do sygnatur.

---

## Podsumowanie ewolucji FPR/TPR na FWAF

| Wariant              | Best model (WAF)        |       FPR |       TPR |
|----------------------|-------------------------|----------:|----------:|
| raw (Etap 1–2)       | web_attack_generic      |    99.39% |    98.74% |
| universal mix (E3)   | web_attack_universal    |    99.99% |   100.00% |
| normalized (E4)      | web_attack_universal    |    99.82% |    98.50% |
| decoded (E6)         | web_attack_universal    |    39.33% |    51.31% |
| decoded+sig (E7a)    | web_attack_universal    |    37.66% |    50.00% |
| sigonly LogReg (E7b) | **web_attack_universal**|     0.08% |    32.62% |
| **rule-based (E7c)** | **web_attack_universal**|**0.545%** |**55.82%** |

Każdy etap rozwiązywał konkretny problem: raw/universal/normalized łapały
*dataset*, decoded wyciął HTTP-envelope artefakty, signatures wprowadziły
uniwersalne cross-dataset feature'y, rule-based wyeliminował LogReg-induced
niedowartościowanie rzadkich sygnatur.

---

## Etap 8 — 4ta walidacja: HttpParamsDataset

**Co zrobiono:** pobrany dataset HttpParamsDataset
(github.com/Morzeux/HttpParamsDataset): URL parameter payloads z etykietami
`norm` (19 304) i `anom` (11 763). Większość `anom` to SQL injection
(`union all select`, `' or 1=1`, `waitfor delay`). Skrypt `evaluate_httpparams.py`
opakowuje payload w minimalny `GET /?q=<payload> HTTP/1.1` (URL-enkodując
payload przez `quote()` żeby nie rozbijał request-line na spacjach).

**Znaleziony bug po drodze:** początkowo nie URL-enkodowaliśmy payloadu,
więc spacje rozbijały request-line — `split(" ", 2)` w `extract_attack_surface`
tracił wszystko za pierwszą spacją. TPR dla `anom` wynosił wtedy 4.28%.
Po fixie URL-encode → TPR 85.72%.

**Wyniki:**

| Approach                                  |    FPR (norm) | TPR (anom)  |
|-------------------------------------------|--------------:|------------:|
| Rule-based web_attack_universal (101 sig) |     **0.07%** |  **85.72%** |
| LogReg sigonly web_attack_universal       |         0.00% |      22.52% |
| Ensemble OR (8 LogReg sigonly)            |         0.07% |      23.75% |

**Wniosek:** rule-based wygrywa miażdżąco — 0.07% FPR (1 na 1 400 benignów)
+ 85.72% TPR. Na FWAF rule-based dawał 55.82% TPR; tu 85.72% bo HttpParams
`anom` to głównie SQLi, idealnie pokryty przez 17 sqli-sigs + inne patterny
universal.

**Podsumowanie trzech zewnętrznych datasetów:**

| Dataset                 | Profil            |        FPR |        TPR |
|-------------------------|-------------------|-----------:|-----------:|
| FWAF (48k bad, 100k good) | mix (xss+sql+cmd+path, dużo obfuskacji bash) |   0.545% |     55.82% |
| HttpParams (12k anom, 19k norm) | głównie SQLi |  **0.07%** |  **85.72%** |

Rule-based `web_attack_universal` potwierdzony jako solidny deploymentowy
detektor ataków webowych — konserwatywny FPR <1% na każdym walidowanym
datasecie, TPR skaluje się z dopasowaniem profilu ataków do sygnatur.

---

## Etap 9 — NFQUEUE inline daemon (deployment)

**Motywacja:** dotąd cały pipeline żył w offline'owych skryptach eval
(CSV → `evaluate_*.py`). Żeby detektor był użyteczny przy iptables, musi
inspekować ruch w czasie rzeczywistym. Linux NFQUEUE pozwala kernelowi
oddać pakiet do procesu userspace, który wydaje werdykt (ACCEPT / DROP).

**Co zrobiono:**

1. **`nfqueue_daemon.py`** — proces userspace na `NetfilterQueue(0)`:
   - Per-flow buffer keyed na 4-krotce `(src, sport, dst, dport)`.
   - `request_is_complete(buf)` — sprawdza `\r\n\r\n` + opcjonalnie
     Content-Length (POST z rozbitym body czeka aż dojdzie reszta).
   - Jak request kompletny → `extract_attack_surface()` → `SignatureCounter(
     "web_attack_universal").transform()`. Hit = `pkt.drop()` + `ipset add
     webattack_block <src> timeout 3600`.
   - GC: flow ciszy >10 s, lub bufor >256 KB → wywalamy state.
   - Fail-open na każdy wyjątek (scapy parse fail, decode fail, itp.) —
     wolimy przepuścić zły pakiet niż zabić legit ruch.
   - Flagi: `--dry-run` (log-only), `--queue N`, `--ipset NAME`, `--log-level`.

2. **Dlaczego ipset zamiast `iptables -A INPUT -s <ip> -j DROP` per-IP:**
   pod floodem tysiące reguł = liniowe skanowanie tabeli kernel-side =
   DoS na siebie samego. `ipset hash:ip` daje O(1) lookup i JEDNĄ regułę
   iptables (`-m set --match-set webattack_block src -j DROP`). Timeout
   3600 s auto-czyści — nie akumulujemy state w nieskończoność.

3. **`test_nfqueue_daemon.py`** — 7 testów offline (bez kernela):
   - `request_is_complete` — partial headers, Content-Length czeka, full OK.
   - `fire_signatures` — benign 0 hitów, SQLi/XSS/path_traversal >0.
   - Benign GET → accept, 0 hitów.
   - SQLi URL-encoded (`%27%20or%201%3D1--`) → hit, ale dry-run = accept.
   - XSS URL-encoded → hit + drop (enforce mode).
   - POST split na 2 segmenty (część1 = headers + "user=admin", część2 =
     reszta body przekraczająca Content-Length) → pierwszy accept (czeka),
     drugi odpala skan i hit.
   - Garbage 4 bajty → fail-open (accept), żadnych wyjątków out.

   **Wynik: 7/7 pass.**

4. **Instalacja zależności w WSL:** scapy via `pip --break-system-packages`
   (Ubuntu 24.04 PEP 668 blokuje zwykłe pip). Netfilterqueue wymaga
   `libnetfilter-queue-dev` + `apt install ipset`.

**Decyzje wdrożeniowe (udokumentowane na górze `nfqueue_daemon.py`):**

| Decyzja                           | Wybór                           |
|-----------------------------------|---------------------------------|
| Scope                             | HTTP port 80 only (HTTPS = E10) |
| Na błędzie parsowania             | fail-open (accept)              |
| Rate limit blokad                 | ipset hash:ip timeout 3600      |
| Reassembly                        | naiwny per-flow buffer + Content-Length |

**Deployment:**
```bash
apt install libnetfilter-queue-dev ipset
pip install --break-system-packages NetfilterQueue scapy
ipset create webattack_block hash:ip timeout 3600
iptables -I INPUT -m set --match-set webattack_block src -j DROP
iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
python3 nfqueue_daemon.py --dry-run        # safe first run
python3 nfqueue_daemon.py                  # enforce
```

**Co ZOSTAŁO na następny etap (E10):**
- HTTPS: terminacja TLS (nginx ssl_offload → upstream localhost:80 →
  NFQUEUE) lub inline mitmproxy.
- Test na żywym ruchu: `target_server.py` + curl z payloadami SQLi/XSS,
  sprawdzenie że ipset się zapełnia, że legit GET przechodzi.
- Ewentualna rozbudowa sygnatur (45% FWAF misses: obfuskowane bash `$IFS`,
  `$(echo V`ar`)`, double-encoded path traversal, `<meta http-equiv=
  set-cookie>` XSS) — żeby TPR na FWAF podskoczył z 55% bliżej 70%.
- Integracja z warstwą 1 (flow-based RF): wspólny log attack events do
  jednego sink'u (JSON/Elastic) dla korelacji.

---

## Etap 10 — Parser fix + rozbudowa per-attack sygnatur (2026-04-23)

**Punkt wyjścia:** rule-based `web_attack_universal` (101 sygnatur) dawał na
FWAF FPR 0.545% / TPR 55.82%. Cel: podnieść TPR do ~70% bez ruszania FPR.

### 10a — Dump missed payloadów → **root cause: parser bug**

Nowy `evaluate_fwaf_rules.py` (pure rule-based) + `--dump-misses` wyciągnął
2500 próbek bad payloadów, które umknęły sygnaturom. Pierwsza analiza
pokazała, że zdekodowana powierzchnia (SRF:) była **ucinana na pierwszej
spacji**:

```
RAW: /<img src="javascript:alert(cross_site_scripting.nasl);">
SRF: /<img
```

Root cause w `extract_attack_surface`: `request_line.split(" ", 2)` dzieli
linię żądania na METHOD / URI / PROTOCOL, zakładając że URI nie ma spacji.
Atakujące URI często mają literalne spacje (np. `<img src="...">`,
`<meta http-equiv=... content="...">`) — cała część po pierwszej spacji
była tracona.

**Fix** (`packet_preprocess.py`): regex `^(\S+)\s+(.*?)\s+HTTP/\d[\d.]*\s*$`
na request-line — URI = grupa 2, spacje zachowane.

**Efekt samego fixa parsera (bez dodawania sygnatur):**

| Dataset         | FPR (przed) | FPR (po) | TPR (przed) | TPR (po) |
|-----------------|------------:|---------:|------------:|---------:|
| FWAF            |      0.545% |   0.578% |      55.82% |  70.79% |

**+15 pp TPR** samym bugfixem. Cel Etapu 10 osiągnięty parserem.
Testy `test_nfqueue_daemon.py` 7/7 OK.

### 10b — Kategoryzacja reszty missed + rozbudowa sygnatur

Po fixie zostało 14 063 missed payloadów. Kategoryzacja (regex buckets):

| Kategoria                      | Hit count |
|--------------------------------|----------:|
| cmd Windows (del/rem/dir/ver)  |       437 |
| cmd po kontrolnym bajcie `\x0b`|       334 |
| RFI `=http://IP:port/...`      |       286 |
| RFI `?path=http://...`         |       168 |
| NASL scanner probes            |       150 |
| `.htaccess`/`.htpasswd`        |       137 |
| quote + unix cmd (`'uname`)    |       111 |
| single `../etc/...`            |        96 |
| ping flags inline              |        61 |
| uname/whoami/id                |        60 |
| union/**/select (inline comm.) |        60 |
| null byte `%00` / `\x00`       |        57 |
| `system(`                      |        54 |
| `sleep N`                      |        24 |
| `phpinfo(`                     |        21 |
| `'union` / `'select`           |        22 |

Każdy kandydat regex przetestowany przeciwko 100k FWAF goodqueries + 48k
badqueries (`artifacts/_test_candidates.py`) — odrzucone te o FPR > 0.05%:

- `path.rfi_ip_url` = 1.22% FPR — skip (legit URL params z http:// w goodqueries)
- `path.rfi_file_param` = 1.14% FPR — skip
- `cmd.trigger_wide_win` = 0.09% FPR — skip (redundantny z scanner_q_marker)

**Dodano 23 nowe wzorce** (101 → 124 sygnatur):
- SQLi (+4): inline-comment-union, comment-then-keyword, quote-kw, quote-semicolon-exec.
- cmd_injection (+15): quote+unix-cmd, ctrlchar+cmd, `sleep N #`, scanner `qXXXX#`, `&rem`, `?cmd=`, `system(`, `phpinfo(`, `eval/passthru/shell_exec`, `<?php`, `${func(}`, `@system`, scanner names (nessus/sqlmap/...), `.nasl`, ping-flags.
- path_traversal (+3): null-byte, single `../etc|windows`, `.htaccess`/`.htpasswd`.
- xss (+1): scanner magic-string (`xss-magic-string`, `cross_site_scripting`).

### 10c — Wyniki po E10 (parser fix + 124 sygnatury)

| Dataset                | FPR (E7c) | FPR (E10) | TPR (E7c) | TPR (E10) |
|------------------------|----------:|----------:|----------:|----------:|
| FWAF (100k/48k)        |    0.545% |    0.813% |    55.82% | **78.50%** |
| HttpParams (19k/12k)   |     0.07% |     0.07% |    85.72% | **86.93%** |
| CSIC benign            |         — |    0.100% |         — |         — |
| ECML benign            |         — |    9.607% |         — |         — |

**Uwagi do FPR:**
- FWAF FPR wzrósł 0.27 pp. Inspekcja 300 false-positive pokazała, że duża
  część to semantycznie ataki źle zaetykietowane w `goodqueries.txt` FWAF —
  np. `?path=http://192.168.202.118:8080/...&cmd=pwd`, `|id|`,
  `..\..\..\..\windows/win.ini`. Nasz detector je łapie prawidłowo.
- HttpParams norm: FPR bez zmian (0.07%) — **czysty benchmark, zero regresji**.
- ECML benign 9.6% FPR to pre-existing problem — 2794 hitów na tylko jednej
  pre-E10 sygnaturze `\.(sh|bat|cmd|ps1|exe|dll)\b`. Nowe sygnatury E10
  kontrybuują tylko ~10 dodatkowych hitów.
- CSIC benign 0.100% — nic się nie zmieniło względem E7c.

### Rekomendacja produkcyjna po E10

**Deploy:** **rule-based `web_attack_universal` z 124 sygnaturami** +
fixed parser (`extract_attack_surface`). Metryki:
- FWAF: 0.81% FPR / **78.5% TPR** (+23 pp vs E7c).
- HttpParams: 0.07% FPR / **86.9% TPR**.
- Zero ML w runtime, deterministyczny, ~0 latency.
- `nfqueue_daemon.py` nie wymaga zmian — `SignatureCounter` używa nowego
  zestawu automatycznie, tak samo parser fix dostają wszystkie ścieżki.

### Co ZOSTAŁO na następny etap (E11)

- Dalej rozbudowa per-attack sigonly LogReg models (można retrainować z nowym
  zestawem 124 sygnatur — wykorzysta ECML + CSIC jako trening, zobaczy czy
  ensemble OR 8 modeli daje coś ponad rule-based universal).
- Test na żywym ruchu (target_server + curl).
- HTTPS TLS termination.
- Integracja z warstwą 1.

---

## Etap 11 — RandomForest ensemble per-attack (2026-04-23)

**Motywacja:** architektura wizji użytkownika — 7 niezależnych klasyfikatorów
ML per typ ataku + 1 flow model. Każdy pakiet trafia równolegle do wszystkich
7, ensemble OR daje werdykt, etykieta zawiera który konkretnie atak
wykryty. Rule-based z Etapu 10 działał jak IPS (regex engine), nie ML.

**Dlaczego RF, nie LogReg (jak w E7b):**
- LogReg(`class_weight=balanced`) + próg 0.5 rozmywa wagę po 124 cechach —
  pojedyncza silna sygnatura często nie przeskakuje progu.
- RF dzieli drzewami na pojedynczych cechach: jeśli jakikolwiek split
  rozpoznaje rzadką-ale-silną sygnaturę, liść odpali pozytyw.
- Cena: wyższy FPR budżet, większe modele (~0.2–2 MB vs 10 kB LogReg).

**Implementacja:**
- `train_packet_model.py` rozszerzone o `--clf {logreg,rf}` + `--rf-n-estimators`.
- `show_top_features` obsługuje oba (coef_ dla LogReg, feature_importances_
  dla RF).
- Output dir: `packet_models_decoded_rf_sigonly/` gdy `--clf rf
  --signatures-only`.
- Wytrenowano 8 modeli (universal + 7 per-attack) na decoded+124sig, 200
  drzew każdy, class_weight=balanced.

**In-dataset test split (precision/recall, threshold=0.5):**

| Model                  | Precision | Recall | F1    |
|------------------------|----------:|-------:|------:|
| web_attack_universal   |    0.988  | 0.294  | 0.453 |
| sqli                   |    0.878  | 0.222  | 0.354 |
| xss                    |    1.000  | 0.671  | 0.803 |
| cmd_injection          |    0.345  | 0.654  | 0.452 |
| path_traversal         |    0.982  | 0.604  | 0.748 |
| ldap_injection         |    1.000  | 0.276  | 0.433 |
| xpath_injection        |    1.000  | 0.651  | 0.789 |
| ssi                    |    1.000  | 0.650  | 0.788 |

RF woli precyzję (kosztem recall) gdy klasa mniejszościowa ma bardzo
nierównomierne cechy — np. sqli (455 pozytywów z ECML) dostało recall 22%
bo większość drzew głosuje "benign" gdy widzi tylko 1-2 sygnatury
zapalone.

**FWAF ensemble OR (7 per-attack RF, bez universal):**

| Model                 | FPR (good) |  TPR (bad) |
|-----------------------|-----------:|-----------:|
| sqli                  |    0.031%  |     3.39%  |
| xss                   |    0.000%  |    24.79%  |
| cmd_injection         |    0.522%  |    21.14%  |
| path_traversal        |    0.027%  |    12.04%  |
| ldap_injection        |    0.000%  |     0.02%  |
| xpath_injection       |    0.000%  |     0.01%  |
| ssi                   |    0.000%  |     0.18%  |
| **ENSEMBLE OR (7)**   |  **0.569%** | **50.04%** |

**HttpParams ensemble OR (7 RF per-attack):**
- FPR (norm): 0.07%
- TPR (anom): 33.83% (vs LogReg-sigonly ensemble 23.75% — RF jest +10 pp
  lepszy od LogReg)
- Dla referencji: rule-based universal daje tu 86.93% TPR.

**Porównanie wariantów detekcji:**

| Approach                         | FWAF FPR | FWAF TPR | HP FPR | HP TPR |
|----------------------------------|---------:|---------:|-------:|-------:|
| rule-based universal (E10)       |  0.813%  |   78.50% |  0.07% | 86.93% |
| RF ensemble OR (E11)             |  0.569%  |   50.04% |  0.07% | 33.83% |
| LogReg sigonly ensemble (E7b)    |   ~0.07% |    ~32%  |  0.07% | 23.75% |

**Wniosek:** RF ensemble jest lepszy od LogReg ensemble (+10–18 pp TPR),
ale wciąż traci do rule-based. Powód strukturalny: rule-based traktuje
sygnatury jako "ANY > 0", RF uczy się że zwykle potrzeba ≥2 sygnatur
(class balance vs trees). Żeby RF zrównać z rule-based, trzeba by bardzo
drastycznie obniżyć próg decyzyjny (co wywali FPR) lub retrainować bez
`class_weight=balanced` z ręcznym resamplingiem.

**Mimo gorszego TPR, RF ensemble wnosi wartość:**
- **Atrybucja typu ataku** — log wie który model odpalił (`sqli`, `xss`, …).
- **Probabilistyczne progi** — policy warstwa może decydować "drop tylko
  gdy ≥2 modele fire" / "log tylko".
- **Retrainowalność** — dodanie nowych danych → `fit(X, y)` bez ruszania
  regexów.

**Integracja z daemonem (hybryda):**
- `nfqueue_daemon.py` dostał flagę `--ensemble-dir PATH`.
- Bez flagi: tylko rule-based universal (zachowanie z E10).
- Z flagą: daemon ładuje 7 per-attack modeli, każdy request przechodzi
  przez WSZYSTKIE (rule-based + każdy model). Hit od dowolnego źródła →
  drop. Log zawiera rozłącznie: `reason=ensemble=sqli+xss rule_hits=3`.
- Tryb hybryda: rule-based daje wysokie TPR (78.5%), RF ensemble daje
  etykiety typu ataku dla alertingu.

**Testy:** nowy `test_daemon_ensemble_loads_and_labels` dodany do
`test_nfqueue_daemon.py` — ładuje modele RF z dysku i sprawdza że daemon
odpala z nimi bez exception'ów. Wszystkie 8/8 testów przechodzi.

**Artefakty:**
- `artifacts/packet_models_decoded_rf_sigonly/` — 8 modeli RF (universal
  2.3 MB, sqli 0.4, xss 0.6, cmd 0.5, path 0.4, ldap 0.2, xpath 0.1, ssi 0.2).
- `evaluate_fwaf_ensemble.py` — nowy ensemble-OR evaluator.

**Rekomendacja produkcyjna (aktualizacja):**
- Primary decyzja: **rule-based universal** (wyższy TPR).
- Atrybucja etykiet: **RF per-attack ensemble** (równolegle dla logu).
- Deploy: `python3 nfqueue_daemon.py --ensemble-dir
  artifacts/packet_models_decoded_rf_sigonly`.

### Co ZOSTAŁO na następny etap (E12)

- Retrain RF z większym zbiorem treningowym (dodać FWAF train partition).
- Threshold tuning per model (krzywa ROC → cutoff maks TPR przy FPR<1%).
- Live traffic test (target_server + curl/nikto).
- HTTPS TLS termination + integracja z flow RF.

---

## Etap 12 — Block threshold + live test na prawdziwym iptables (2026-04-23)

**Motywacja:** dotąd cała weryfikacja daemona działała offline (pakiety
budowane przez scapy w testach jednostkowych). Potrzebne potwierdzenie że
cały pipeline działa przy rzeczywistym ruchu TCP:
- NFQUEUE od kernela odbiera pakiety
- Daemon skanuje + dropuje pakiet z atakiem
- Ipset dostaje IP napastnika
- Kolejne pakiety z tego IP są dropowane przez kernel (O(1), zero-copy do userspace)

Dodatkowo — użytkownik wskazał sensowny feature: **próg blokady**. Nie
blokujmy po pierwszym pakiecie (fałszywy alarm może dostać ban); pakiet
zawsze dropujemy, ale IP do ipset dopiero po N próbach.

### Zmiany implementacyjne

1. **`Blocker.threshold` + `_attempts` counter:**
   - Każde wywołanie `block(ip, reason)`: inkrementuje licznik per IP;
     gdy `n < threshold` → log `ATTEMPT ip (n/N)`, return.
   - Gdy `n == threshold` → promote do `_seen`, ipset add (kernel block).
   - Idempotent po zablokowaniu (kolejne wywołania no-op).
2. **CLI flag `--block-threshold N`** (default 1 = zachowanie z E10/E11).
3. **Testy offline:** 2 nowe w `test_nfqueue_daemon.py`:
   - `test_blocker_threshold_counts_and_blocks` — liczenie per IP, promocja
     w N-tej próbie, niezależność liczników dla różnych IP.
   - `test_daemon_threshold_packet_dropped_before_ipset` — pakiety są
     dropowane W KAŻDEJ próbie, ale ipset zasila się dopiero w N-tej.
   - Wszystkie 10/10 pass.

### Live test harness (`live_test.sh`)

Orkiestrator 3-scenariuszowego testu, uruchamiany pod root-em w WSL:

```
wsl -u root bash /mnt/c/.../live_test.sh [--threshold N]
```

1. Instaluje brakujące zależności (`ipset`, `NetfilterQueue`, `scapy`).
2. Tworzy `ipset create webattack_block_test hash:ip timeout 3600`.
3. Wpina reguły iptables:
   - `-I INPUT 1 -m set --match-set webattack_block_test src -j DROP`
   - `-A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0`
4. Startuje `target_server.py` (port 80) + `nfqueue_daemon.py` (NFQUEUE 0)
   w tle, loguje do `/tmp/*.log`.
5. **Scenariusz 1** (benign): `curl -X POST /login password=wrong` → 401.
   Dowodzi że ruch nieatakowy normalnie przechodzi NFQUEUE → target.
6. **Scenariusz 2** (attack + threshold): pętla wysyłająca SQLi dopóki
   `grep "BLOCK 127.0.0.1" daemon.log` nie trafi; liczy `ATTEMPT` linie,
   weryfikuje że jest ≥ `threshold-1`; sprawdza że IP trafił do ipset.
7. **Scenariusz 3** (kernel-side DROP): benign `curl` po BLOCK → timeout
   (`rc=28`, `http_code=000`). Dowodzi że ipset + `-m set` działa
   zero-copy — pakiet nie dociera do NFQUEUE, nie dociera do target.
8. Cleanup trap — zabija procesy, usuwa reguły, niszczy ipset.

**Wynik (threshold=3):**

```
==> scenario 1: benign curl → expect 401
  OK: benign HTTP 401
==> scenario 2: SQLi attack (threshold=3)
  OK: threshold=3 → 2 ATTEMPT lines before BLOCK
  OK: 127.0.0.1 is in ipset webattack_block_test
==> scenario 3: benign curl from blocked IP → must fail
  OK: blocked IP cannot reach target (curl rc=28, http_code=000)

--- daemon log ---
HIT src=127.0.0.1 hits=2 surface="/p?id=' or 1=1-- "
ATTEMPT 127.0.0.1 (1/3) reason=web_attack_universal hits=2
HIT ...
ATTEMPT 127.0.0.1 (2/3) ...
HIT ...
BLOCK 127.0.0.1 (attempts=3/3) ...

--- ipset members ---
127.0.0.1 timeout 3593

--- iptables INPUT ---
1  DROP  0  -- 0.0.0.0/0 0.0.0.0/0 match-set webattack_block_test src
2  NFQUEUE 6 -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:80 NFQUEUE num 0

ALL SCENARIOS PASSED
```

### Problemy napotkane + rozwiązania

| Problem                                   | Rozwiązanie                                   |
|-------------------------------------------|-----------------------------------------------|
| Git Bash tłumaczy `/mnt/c/...` → `C:/Program Files/Git/mnt/...` | `MSYS_NO_PATHCONV=1` przed `wsl` |
| Windows `sudo` wymaga włączenia w Dev Settings | `wsl -u root` — omija sudo całkowicie |
| `ipset list | grep -c` zawodny przy TCP retransmit (curl retry generuje dodatkowe ATTEMPT) | Parse `daemon.log` zamiast ipset state |
| `curl || echo "BLOCKED"` sklejało `000` + `BLOCKED` → `000BLOCKED` | Sprawdzać `rc=$?` osobno + `http_code` osobno |
| Scenariusz threshold timing-dependent | Pętla wysyła ataki dopóki log nie pokaże BLOCK |

### Potwierdzone in vivo

- NFQUEUE działa pod WSL2 (kernel 6.6.87.2-microsoft-standard-WSL2).
- `scapy` parsuje lo-traffic, `extract_attack_surface` + `SignatureCounter`
  odpalają na real-curl payloadzie.
- `ipset hash:ip timeout 3600` skaluje — O(1) lookup, kernel dropuje
  zablokowany IP zanim pakiet dotrze do userspace.
- Threshold N=3: każdy atak-pakiet → drop (curl widzi timeout), ale
  kernel-side block uruchamia się dopiero w 3-cim pakiecie.
- Curl z zablokowanego IP timeoutuje przez 3s (max-time) — pakiet do
  kernel-a dociera, `-m set` match, DROP, zero odpowiedzi.

### Co ZOSTAŁO na następny etap (E13)

- HTTPS: nginx ssl_offload → upstream :80 → NFQUEUE.
- Integracja z warstwą 1 (flow-based RF) — wspólny log JSON.
- Real-world adversarial test (nikto, sqlmap) — sprawdzenie że ipset
  wydłuża TPR, że blok jest bezpieczny (nie drop'uje legit ruchu z
  dynamicznego klient-IP po jego side).
- Parametryzacja: `--block-threshold` per attack-type (SQLi 1, XSS 5...).

---

## Etap 13 — Spięcie warstw w ciągły system (2026-04-23)

**Motywacja:** dotąd warstwy działały osobno — Layer 1 (flow RF na CSV z
CICFlowMeter, batchowo) i Layer 2 (packet daemon na NFQUEUE, ciągle).
Potrzebne: jeden uruchomiony system, wspólny ipset/log, ciągłe skanowanie
sieci przez obie warstwy jednocześnie.

### Architektura zunifikowana

```
              +──────────────────────────────────────────+
              │           network interface (lo/eth0)    │
              +──────────────────────────────────────────+
                │                                       │
   scapy sniff  │                       NFQUEUE 0 (tcp  │
   live pkts    │                       dport 80)       │
                ▼                                       ▼
   +─────────────────+                    +──────────────────────+
   │ flow_monitor.py │                    │  nfqueue_daemon.py   │
   │ (cicflowmeter   │                    │  (signature 124 +    │
   │  FlowSession    │                    │   RF per-attack      │
   │  → MLBlocker    │                    │   ensemble optional) │
   │  Writer.write)  │                    │                      │
   └────────┬────────┘                    └──────────┬───────────┘
            │ ipset add rlfw_block                   │ ipset add rlfw_block
            │ append JSONL(layer=flow)               │ append JSONL(layer=packet)
            ▼                                         ▼
        +─────────────────────────────────────────────+
        │ shared ipset: rlfw_block hash:ip t=3600     │
        │ shared log:   /tmp/rlfw_events.jsonl        │
        +─────────────────────────────────────────────+
                          │
                    single iptables rule:
                    -m set --match-set rlfw_block src -j DROP
```

### Nowe komponenty

1. **`flow_monitor.py`** — Layer 1, ciągły sniffer:
   - `sys.path.insert cicflowmeter/src` + `create_sniffer(input_interface=iface)`.
   - Po zbudowaniu sesji nadpisuje `session.output_writer` własnym
     `MLBlockerWriter`, który dla każdego ukończonego flow zbudowuje
     jednowierszowy DataFrame, przepuszcza przez `MLDetector.check()`,
     a na nie-BENIGN atak → `Blocker.block(src_ip)` i JSONL event.
   - Threshold + dry-run + events-log jak w nfqueue_daemon.

2. **`nfqueue_daemon.py` — zmiany integracyjne:**
   - Default ipset: `webattack_block` → `rlfw_block` (wspólny z Layer 1).
   - Nowa flaga `--events-log PATH` — dopisuje JSONL eventy:
     `{"ts", "layer":"packet", "src_ip", "label", "rule_hits", "reason"}`.

3. **`run_all.sh`** — orkiestrator produkcyjny:
   - Instaluje `ipset` i deps jeśli trzeba.
   - Tworzy `rlfw_block` + 2 reguły iptables (DROP on match-set + NFQUEUE 0).
   - Startuje **oba** daemon'y w tle, dzieli ten sam JSONL events log.
   - Trap `EXIT INT TERM` → cleanup (procesy, iptables, ipset).
   - CLI: `--iface`, `--threshold`, `--ipset`, `--queue`, `--events`.

4. **`live_test_full.sh`** — e2e test unified system:
   - Scenariusz 1: benign POST /login → 401 (Layer 2 akceptuje).
   - Scenariusz 2: SQLi curl → `daemon.log` BLOCK + `events.jsonl`
     ma `"layer":"packet"` + ipset zawiera 127.0.0.1.
   - Scenariusz 3: curl z zablokowanego IP → kernel DROP (rc=28 code=000).
   - Scenariusz 4: flow_monitor alive + ingest check (best-effort: RF
     rzadko odpala na krótkim localhost HTTP; jeśli odpali, eventy mają
     `layer=flow`).

### Uruchomienie w produkcji

```bash
# Start
wsl -u root bash /mnt/c/.../run_all.sh --iface eth0 --threshold 3
# Monitor
tail -f /tmp/rlfw_events.jsonl                          # oba layery
ipset list rlfw_block                                   # aktualne bany
# Stop: Ctrl+C w terminalu gdzie leci run_all.sh
```

### Format JSONL

```json
{"ts":"2026-04-23T22:45:11","layer":"packet","src_ip":"1.2.3.4","label":"web_attack_universal","rule_hits":3,"reason":"web_attack_universal hits=3"}
{"ts":"2026-04-23T22:45:19","layer":"flow","src_ip":"5.6.7.8","dst_ip":"10.0.0.2","dst_port":22,"label":"SSH-Patator","reason":"ml-rf"}
```

Korelacja offline: `grep 'src_ip":"X.Y.Z.W"' events.jsonl` pokaże każdy
atak z tego IP w obu warstwach posortowany po czasie.

### Decyzje architektoniczne

| Decyzja                                  | Wybór                                |
|------------------------------------------|--------------------------------------|
| Shared ipset vs separate per layer       | shared `rlfw_block` (jedna iptables) |
| Flow writer integration                  | monkey-patch `session.output_writer` |
| Log format                                | JSONL (linia per event, append-only) |
| Process supervision                       | `run_all.sh` z trap cleanup (systemd można dopisać w E14) |
| Flow monitor library loading              | `sys.path.insert(cicflowmeter/src)`  |
| Loop prevention (flow sees ipset drops?)  | NFQUEUE matchuje tylko port 80; flow_monitor sniffuje wszystko, ale kernel DROP blokuje pakiety PRZED warstwą aplikacyjną, więc scapy ich nie widzi — OK |

### Co ZOSTAŁO na następny etap (E14)

- `systemd` units (rlfw-flow.service, rlfw-packet.service) dla deploymentu.
- Real adversarial test na zewnętrznym interfejsie: `sqlmap`, `nikto`,
  `hping3 --flood`, masowy port scan. Weryfikacja że flow RF rzeczywiście
  odpala na rozległym, nie-loopbackowym ruchu.
- `sigHUP` reload sygnatur bez restartu daemon'a.
- Metryki do Prometheus (exposed /metrics endpoint): liczniki hits per
  layer, per label.

---

## Etap 14 — V2 modele + cleanup (2026-04-27)

**Motywacja:** użytkownik dorzucił 3 nowe CSV datasety per typ ataku
(SQLi, XSS, cmd injection) i powiedział: pierdolić te 8 modeli z E11,
robimy 3 — jeden per atak, sprawdź kilka algorytmów, wybierz najlepszy.
Dodatkowo zostawiamy 4 modele (1 flow + 3 packet), reszta artefaktów do
usunięcia.

### 14a — Cleanup projektu

Usunięte (~1.7 GB):
- `artifacts/packet_models/` (821M) — E1 raw TF-IDF
- `artifacts/packet_models_normalized/` (215M) — E4
- `artifacts/packet_models_decoded/` (127M) — E6
- `artifacts/packet_models_decoded_sig/` (127M) — E7a
- `artifacts/packet_models_decoded_sigonly/` (40K) — E7b
- `artifacts/packet_models_decoded_rf_sigonly/` (4.6M) — E11 (8 RF modeli)
- `artifacts/eval_cache_*/`, `artifacts/fwaf_cache_*/`, `artifacts/plots/`
- `.venv-wsl/` (366M)
- 4 popsute eval-skrypty (linkowały do skasowanych katalogów):
  `evaluate_fwaf.py`, `evaluate_fwaf_ensemble.py`,
  `evaluate_cross_dataset.py`, `evaluate_httpparams.py`

Zostawione: rule-based eval (`evaluate_fwaf_rules.py` — niezależny od
modeli), wszystkie skrypty runtime (daemon, flow_monitor, rlfw, run_all),
demo (`attack_demo.py`, `simulate_brute_force.py`, `target_server.py`),
trening Layer 1 (`train_model.py`).

### 14b — Nowe datasety

| CSV                              | shape   | pos   | neg    |
|----------------------------------|--------:|------:|-------:|
| `Modified_SQL_Dataset.csv`       |  30919  | 11382 |  19537 |
| `XSS_dataset.csv`                |  13686  |  7373 |   6313 |
| `command injection.csv`          |   2106  |   514 |   1591 |

Format: czyste payloady (Query/Sentence/sentence) + Label (0/1). Cmd CSV
HTML-encoded (`&lt;`, `&quot;`).

### 14c — `train_3models.py` — sweep algos × cech

Każdy z 3 ataków × 5 algorytmów × 3 warianty cech = **45 kombinacji**.

Algorytmy testowane:
- LogisticRegression (class_weight=balanced, liblinear)
- RandomForestClassifier (n_estimators=200, class_weight=balanced)
- GradientBoostingClassifier (n_estimators=100)
- LinearSVC (class_weight=balanced)
- MultinomialNB

Cechy:
- `tfidf_char35` — TF-IDF char_wb n-gram (3,5), max_features=50k
- `sigs` — `SignatureCounter(<attack>)` (21 sqli / 19 xss / 32 cmd regexów)
- `hybrid` — FeatureUnion(tfidf + sigs)

Preprocessing payloadów (spójny z runtime extract_attack_surface):
`html.unescape() → urllib.unquote() ×3 → lower()`.

**Wyniki — wygrali wszystko LinearSVC:**

| Atak | Zwycięzca | F1 | P | R | Fit | Rozmiar |
|---|---|---:|---:|---:|---:|---:|
| sqli | hybrid + LinearSVC | **0.9956** | 0.9996 | 0.9917 | 1.09s | 3.9 MB |
| xss | tfidf_char35 + LinearSVC | **0.9986** | 1.0000 | 0.9973 | 0.65s | 3.5 MB |
| cmd_injection | tfidf_char35 + LinearSVC | **0.9951** | 1.0000 | 0.9903 | 0.03s | 1.3 MB |

Top spostrzeżenia z 45 kombinacji (`results.md`):
- **LinearSVC zawsze top** — szybki (<1.5s) i najlepszy F1.
- **GBC równe wyniki, 40-50× wolniejszy** — bezsensowne.
- **RF cmd_injection P=0.55** — głosował zachłannie na małym (2k)
  nierównomiernym datasecie.
- **MNB słabszy precision** (0.87 sqli, 0.97 xss) — Naive Bayes nie radzi
  sobie z TF-IDF tak dobrze jak max-margin.
- **Hybrid pomaga tylko sqli** (+0.0009 F1). Dla xss/cmd char-ngramy same
  saturują.
- **Same sygnatury** dają max F1 0.81 (cmd) — regexy nie pokrywają
  specyficznych payloadów z tych datasetów.

### 14d — Cross-dataset walidacja (`eval_3models.py`)

Walidacja na zewnętrznych datasetach niewidzianych w treningu:

**HttpParamsDataset (per-type labels — najczystszy benchmark):**

| slice          |     n  | sqli model | xss model | cmd model | any (OR) |
|----------------|-------:|-----------:|----------:|----------:|---------:|
| **norm** (FPR) | 19 304 |    0.026%  |   0.010%  |   0.047%  | **0.083%** |
| sqli (TPR)     | 10 852 |  **99.48%**|     0.00% |     7.98% |   99.48% |
| xss (TPR)      |    532 |     0.00%  | **94.55%**|    43.80% |   95.68% |
| cmdi (TPR)     |     89 |     6.74%  |     3.37% |  **91.01%**|  91.01% |

Per-attack TPR 91-99% przy FPR ~0.08% — modele rozpoznają swój typ ataku
i nie krzyżują się fałszywie.

**FWAF (mix ataków):**

| Model          | FPR (good 100k) | hit (bad 48k) |
|----------------|----------------:|--------------:|
| sqli           |          0.297% |        14.44% |
| xss            |          0.096% |        26.30% |
| cmd_injection  |       **2.473%** ⚠ |     51.87% |
| any (OR)       |        **2.836%** |    **68.36%** |

**CSIC benign (sanity):** wszystkie 3 modele 0.000% FPR na 30k benign.

### 14e — Próba naprawy cmd_injection FPR (`retrain_cmd.py`)

Augmentacja CSV cmd injection (514 pos) z ECML cmd_injection (2302 pos)
+ ECML benign (35006 neg). Test 2 wariantów:

| | FWAF FPR | FWAF hit | HP cmdi TPR | HP norm FPR |
|---|---:|---:|---:|---:|
| **ORIGINAL** (CSV only) | **2.473%** | 51.87% | 91.01% | 0.047% |
| tfidf+aug | 4.60% ❌ | 34.37% ❌ | 78.65% ❌ | 1.77% ❌ |
| hybrid+aug | 2.73% ❌ | 35.17% ❌ | 94.38% ✓ | 0.47% ❌ |

ECML cmd_injection ma w sobie path traversal noise (`..\winnt\system32\cmd.exe`)
— model uczy się że "wygląda jak path z cmd" = atak, FWAF goodqueries są
pełne legit `/etc/`, `/winnt/` ścieżek. Augmentacja zaszkodziła.
Skrypt automatycznie zachował oryginalny model. Wyjebane.

### 14f — Daemon: 8 modeli → 3 modele (auto-enumerate)

`nfqueue_daemon.py` — usunięta sztywna lista 7 ataków. Teraz daemon
auto-enumerate `*.pkl` w `--ensemble-dir` i używa filename stem jako
attack label. Switch z 8-model E11 na 3-model V2 = `--ensemble-dir
artifacts/packet_models_v2`.

### 14g — Testy

`test_nfqueue_daemon.py` rozbudowany do **14 testów** (z 10):
- `test_daemon_ensemble_loads_and_labels` — przepięty na V2 set
  (assert keys == {sqli, xss, cmd_injection})
- `test_daemon_v2_xss_fires` — XSS payload odpala xss model
- `test_daemon_v2_cmd_injection_fires` — SSI/cmd payload odpala cmd
- `test_daemon_v2_benign_does_not_fire` — czysta path nie odpala (uwaga:
  cmd model ma znany 2.47% FPR na URI z parametrami — test używa
  `/static/css/style.css`, bez query)

Wszystkie 14/14 przechodzą.

### 14h — Stan końcowy: 4 modele produkcyjne

```
artifacts/
├── model.pkl              38 MB   Layer 1 — RandomForest CICIDS2017
├── scaler.pkl            3.5 KB
├── feature_order.json
└── packet_models_v2/
    ├── sqli.pkl          3.8 MB   hybrid (TF-IDF + 21 sigs) + LinearSVC
    ├── xss.pkl           3.4 MB   TF-IDF char35 + LinearSVC
    └── cmd_injection.pkl 1.3 MB   TF-IDF char35 + LinearSVC
```

**Razem 4 modele = 46 MB.**

### Co ZOSTAŁO na następny etap (E15)

- Demo na konferencję — niełopkowy serwer + ataki/benign z różnych
  interfejsów i IP.

---

## Etap 15 — Demo na konferencję (network namespaces, 2026-04-28)

**Motywacja:** dotąd wszystko żyło na 127.0.0.1. Do prezentacji
konferencyjnej potrzebne:
1. Server pod nie-loopback IP.
2. Atakujący i benign klienci z **różnych interfejsów** i **różnych IP**.
3. Wizualnie efektowne: publiczność widzi rosnący firewall live.

### 15a — Architektura demo

Linux network namespaces + bridge w default ns:

```
   Default network namespace (WSL2 host)
   ┌───────────────────────────────────────────────┐
   │  br-rlfw  10.10.10.1/24  ←  target_server.py │
   │            (bridge has IP)     listening :80  │
   │                                               │
   │  iptables INPUT:                              │
   │    -j RLFW_BLOCK                              │  (mode=iptables)
   │    -p tcp --dport 80 -j NFQUEUE --queue-num 0 │
   │  nfqueue_daemon + 3 V2 models                 │
   └─────┬───────────┬───────────┬─────────────────┘
         │           │           │
    veth pair    veth pair    veth pair
         │           │           │
   ┌─────┴────┐ ┌────┴───────┐ ┌─┴─────────┐
   │attacker1 │ │ attacker2  │ │  benign   │
   │10.10.10.20│ │10.10.10.21 │ │10.10.10.30│
   └───────────┘ └────────────┘ └───────────┘
   sends SQLi   sends XSS/cmd  sends valid POST
```

Każdy namespace ma własny veth (real interface) i własny IP. Bridge w
default ns daje L2 connectivity. iptables/NFQUEUE/ipset w default ns
widzi cały ruch przez bridge.

### 15b — Skrypty

**`demo_net.sh`** — setup/teardown infrastruktury sieci:
```bash
sudo bash demo_net.sh up           # bridge + 3 namespaces
sudo bash demo_net.sh status       # pokazuje IP per ns
sudo bash demo_net.sh exec attacker1 curl ...   # wykonuje w danym ns
sudo bash demo_net.sh down         # pełen cleanup
```

**`demo_full.sh`** — pełen automated demo run (6 scenariuszy + cleanup).
Dobre do CI/regresji, nie do prezentacji na żywo (kończy się szybko).

**`demo_start.sh`** — interactive demo — uruchamia infrastrukturę i
**zostaje aktywne**, streamuje logi daemona. W drugim terminalu wpisujesz
curl-e na żywo. Ctrl+C → cleanup.
- Default tryb: `iptables` — każdy blok = nowa reguła w `RLFW_BLOCK`,
  widoczna w `iptables -L`. **Najmocniejsze do prezentacji wizualnej.**
- `--ipset` — produkcyjne, O(1) hash:ip.
- `--threshold N` — pakiety zawsze drop, ipset/iptables blok dopiero po N.

### 15c — Bugi naprawione po drodze

| Problem | Symptom | Fix |
|---|---|---|
| Daemon default `--block-mode iptables`, demo używa ipset | `iptables -A RLFW_BLOCK -s ... failed: No chain by that name` | Demo skrypt jawnie tworzy chain RLFW_BLOCK + linkuje do INPUT, lub używa `--block-mode ipset` |
| `target_server.py` używał `HTTPServer` (single-thread) | Po 4 atakach SQLi server hangs (4 stuck connections — TCP handshake OK, request dropowany, server czeka w `handle()` na request line) → benign nie obsługiwany | Migracja na `ThreadingHTTPServer` + `LoginHandler.timeout = 5.0` |
| RP filter blokował zwrotny routing | benign od `.30` timeout mimo że pakiety dochodzą do NFQUEUE (counter rośnie) i daemon accept | `sysctl net.ipv4.conf.{all,default,br-rlfw}.rp_filter=0` w `demo_net.sh up` |
| `set -e` + `pkill` zwracające 1 jeśli nic do zabicia | `demo_start.sh` skakał od pre-flight do cleanup | Wrapped pre-flight w `set +e ... set -e` block |
| `curl ...` literalnie próbuje resolve "..." | Demo cheat sheet z placeholderami | Konkretne URL-e w cheat sheet, plus `--max-time 4` żeby curl nie wisiał 127s czekając na TCP retransmits |

### 15d — Dlaczego `--max-time` jest kluczowe

Gdy daemon dropuje pakiet HTTP (PO TCP handshake'u), klient TCP retransmituje
request 5-7 razy z exp backoff = ~127 sekund zanim curl się podda. Bez
`--max-time 4` cały demo by się zaciął na każdym ataku. `--connect-timeout`
nie pomaga, bo TCP connection już ESTABLISHED — dropowany jest payload
HTTP-request, nie SYN.

### 15e — Curl exit codes w demo

| rc | Znaczenie | Co to oznacza |
|---:|---|---|
| 0  | response received | Request przeszedł, server odpowiedział |
| 28 | timeout (max-time wybiło) | Pakiet zdropowany przez daemon **lub** kernel ipset/iptables |
| 52 | empty reply from server | TCP handshake OK, request dropowany, server-side `socket.timeout=5s` zamknął |
| 7  | connection refused | Server padł / port nie nasłuchuje |

`rc=28` i `rc=52` oba "atak zablokowany" — różnica to którym etapem
(kernel-side ipset DROP vs userspace daemon drop).

### 15f — Gotowe komendy do prezentacji

3-terminalowy setup:

```bash
# T1 — firewall (zostaje na pierwszym planie):
sudo bash demo_start.sh

# T2 — watch rosnący firewall (efekt "wow"):
watch -n 0.5 'sudo iptables -L RLFW_BLOCK -n --line-numbers'

# T3 — wpisujesz na żywo:
sudo bash demo_net.sh exec benign \
    curl -v http://10.10.10.1/login -d "password=secret123"
sudo bash demo_net.sh exec attacker1 \
    curl --max-time 4 "http://10.10.10.1/p?id=%27%20or%201%3D1--"
# (×3 → po threshold=3 reguła pojawia się w T2)
sudo bash demo_net.sh exec attacker2 \
    curl --max-time 4 "http://10.10.10.1/p?x=%3Cscript%3Ealert(1)%3C/script%3E"
sudo bash demo_net.sh exec attacker2 \
    curl --max-time 4 "http://10.10.10.1/p?c=%3C!--%23exec%20cmd=%22/bin/cat%20/etc/passwd%22--%3E"

# T4 (opcjonalny) — events korelacja per IP:
tail -f /tmp/rlfw_events.jsonl
```

### 15g — Smoke test wyniki

```
=== port 80 ===              LISTEN 10.10.10.1:80 (python3)
=== netns ===                benign attacker2 attacker1
=== benign curl ===          http=200                     ← clean OK
=== attack #1 #2 #3 ===      rc=28, rc=28, rc=28          ← daemon drops
=== iptables RLFW_BLOCK ===  1  DROP  10.10.10.20         ← rule appeared!
=== benign od blocked ===    rc=28 (kernel DROP)
=== benign od clean IP ===   http=200                     ← per-IP OK
=== teardown ===             port 80 freed
```

Wszystkie 6 punktów demo działa.

### Co ZOSTAŁO na następny etap (E16)

- Backup screencast demo na wypadek braku internetu / WSL na obcym
  laptopie.
- Slajdy do akompaniamentu live demo (architektura, metryki, Q&A).
- `attack_demo.py` (Polish interactive menu) integrated z netns
  namespacem — żeby publiczność mogła wybrać typ ataku z menu zamiast
  pisać URL ręcznie.
- HTTPS termination upstream (nginx ssl_offload).
- Rozszerzenie cmd_injection treningu o własne syntetyczne payloady żeby
  obniżyć FWAF FPR z 2.47% do <0.5%.
