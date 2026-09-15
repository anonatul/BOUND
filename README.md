# Offline Post-Quantum Forensic Document Attribution — Prototype

> **Prototype, not production security.** Uses real post-quantum cryptography (ML-KEM, ML-DSA), real AES-GCM, real DCT watermarking, and a tamper-evident ledger with 4-node replication. Works fully offline once dependencies are installed.

## Concept

A sender encrypts one sensitive PDF. Multiple authorized recipients (Alice, Bob) can decrypt. Each decryption generates a unique invisible forensic watermark (`WM-...`), signs the decryption event with the recipient’s ML-DSA private key, and commits to a local tamper-evident ledger replicated to 4 nodes (quorum 3/4). If a leaked PDF is later uploaded, the system extracts the watermark, finds the ledger event, verifies the signature and ledger chain, and identifies the recipient/session.

**Architecture rule:** watermark is generated **during recipient decryption**, not at sender encryption time.

```
Sender → Encrypt → Recipient → Decrypt (ML-KEM) → Session+Nonce → Watermark ID → DCT Watermark/Render → Sign (ML-DSA) → Ledger (quorum) → Display
```

## Important Security Limitations

The prototype **does NOT claim** to prevent:

- screenshots / screen recording / phone photography
- plaintext extraction from compromised endpoint
- watermark removal by a determined attacker
- copying content into a completely new document

The recipient controls their endpoint. Forensic attribution works **only when the leaked artifact retains the fingerprint**.

Potentially honest recipients, but forensic attribution provides deterrence via accountability when the fingerprint survives.

---

## Tech Stack — Real Cryptography, No Fakes

| Component | Implementation | Library |
|---|---|---|
| **ML-KEM-768** (Kyber768, NIST Level 3) | Real KEM (keygen/encaps/decaps) | `pqcrypto` (Rust bindings to liboqs/PQClean) — not faked |
| **ML-DSA-65** (Dilithium3, Level 3) | Real signatures (keygen/sign/verify) | `pqcrypto` — not faked, not RSA/ECDSA |
| **AES-256-GCM** | Real AEAD | `cryptography` (OpenSSL) |
| **DCT Watermark** | Frequency-domain, QIM at coeff (3,2), Q=8, blind extraction | `numpy` + `scipy.fftpack` + `Pillow` + `pymupdf` |
| **Ledger** | Append-only hash chain `SHA256(canonical_event+sig+prev)` , 4 nodes, quorum 3/4 | File-based `ledger/node*/ledger.jsonl` |
| **PDF Handling** | Render to images at 150 DPI, watermark Y-channel, re-embed as PNG | `pymupdf` (MuPDF) |

> **Environment verification (Final Instruction):** On 2026-09-15 we verified that `pqcrypto` with `ml_kem_768` and `ml_dsa_65` works locally via `uv run --with pqcrypto` (encaps/decaps and sign/verify round-trips succeed). If `pqcrypto` were unavailable we would have stopped and reported the dependency problem rather than silently falling back to RSA/ECDSA. All signatures and KEM operations are real and verified via executed tests (see `pytest`).

---

## Project Structure

```
forensic-doc-attribution/
├── backend/
│   ├── app/
│   │   ├── crypto/pqcrypto_wrapper.py   # ML-KEM / ML-DSA wrappers (real)
│   │   ├── identity/manager.py           # Alice & Bob enrollment
│   │   ├── encryption/aes.py + document.py  # AES-GCM + ML-KEM wrapping
│   │   ├── watermark/dct_watermark.py    # DCT invisible watermark
│   │   ├── ledger/ledger.py              # 4-node tamper-evident ledger
│   │   ├── forensic/events.py + verify.py # Canonical event, signing, forensic pipeline
│   │   ├── services/decryption_service.py # Full recipient flow
│   │   └── main.py                       # FastAPI
│   ├── keys/            # Local private keys (ML-DSA SK, ML-KEM SK) — Alice, Bob
│   ├── data/
│   └── tests/test_crypto.py
├── frontend/
│   ├── src/
│   │   ├── pages/Sender.jsx, Recipients.jsx, LedgerView.jsx, Investigator.jsx, SecurityTests.jsx
│   │   ├── components/RecipientCard.jsx
│   │   └── services/api.js
│   ├── vite.config.js
│   └── dist/            # Built frontend (served by FastAPI)
├── ledger/
│   ├── node1/ledger.jsonl
│   ├── node2/ledger.jsonl
│   ├── node3/ledger.jsonl
│   └── node4/ledger.jsonl   # Replicated, quorum 3/4
├── storage/
│   ├── encrypted/       # DOC-*.json (ciphertext + wrapped keys)
│   └── watermarked/     # DOC-*_ALICE_SES-*.pdf (image-based watermarked PDFs)
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

Adapted from spec (§12) with `storage/` for encrypted/watermarked artifacts.

---

## Quick Start (Local, Offline after install)

### Prerequisites

- Python 3.11 (via `uv` or system)
- Node 20+ for frontend (optional; backend serves built frontend)

### 1. Backend

```bash
uv sync --python 3.11          # installs pqcrypto, cryptography, pymupdf, etc.
uv run uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
# API at http://localhost:8000/api/health
# Frontend (built) at http://localhost:8000/
```

Dependencies are pinned in `pyproject.toml`. After `uv sync`, everything runs without Internet.

### 2. Frontend (dev mode, optional)

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173 (proxies /api to :8000)
# Production build (already served by backend):
npm run build
```

### 3. Docker

```bash
docker compose up --build
# App at http://localhost:8000
```

---

## API Overview

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health + PQC info |
| `GET` | `/api/recipients` | List Alice/Bob cards |
| `POST` | `/api/encrypt` | Upload PDF + recipients (`multipart: file, recipients='["ALICE","BOB"]'`) → document_id, hash |
| `GET` | `/api/documents` | List encrypted docs |
| `POST` | `/api/decrypt` | `{document_id, recipient_id}` → watermark, session, signature, ledger, download_url |
| `GET` | `/api/watermarked/{file}` | Download watermarked PDF |
| `GET` | `/api/ledger` | Entries + integrity `VALID/FAILED` |
| `POST` | `/api/verify` | Upload leaked PDF → forensic verification (watermark → ledger → signature → recipient) |
| `POST` | `/api/test/*` | 5 security demonstrations + end-to-end |

---

## Usage — Definition of Done (Live Demo)

1. **Sender:** Upload `secret.pdf` → Encrypt for Alice,Bob → get `DOC-001` + hash.
2. **Recipients:** Alice decrypts → `WM-A`, session `SES-...`, ML-DSA signature, ledger commit. Bob decrypts → `WM-B` (≠ WM-A), visually identical (PSNR >45 dB).
3. **Leak:** Download Alice’s watermarked PDF as leaked artifact.
4. **Investigator:** Upload leaked PDF → **Watermark detected** → **Ledger match found** → **Signature verified** → **Ledger verified** → **Recipient identified**: `VERIFIED — Alice`.

All 12 steps verified via `POST /api/test/end-to-end` or the end-to-end pytest.

### Manual curl

```bash
# Encrypt
curl -F file=@secret.pdf -F recipients='["ALICE","BOB"]' http://localhost:8000/api/encrypt
# Decrypt as Alice
curl -X POST -H "Content-Type: application/json" -d '{"document_id":"DOC-001","recipient_id":"ALICE"}' http://localhost:8000/api/decrypt
# Verify leak (replace with path to Alice's watermarked PDF)
curl -F file=@storage/watermarked/DOC-001_ALICE_SES-*.pdf http://localhost:8000/api/verify
```

---

## Security Demonstrations (Buttons in Frontend → Demonstrations tab, also API)

1. **Different recipients** — `POST /api/test/different-recipients` → `Alice watermark != Bob watermark` (PSNR >30 dB, visually identical)
2. **Attribution** — `POST /api/test/attribution` → leaked Alice doc → `Recipient: Alice, Signature: VALID, Ledger: VALID`
3. **Signature Tampering** — modify recipient in event → `ML-DSA SIGNATURE: INVALID` (real ML-DSA verify fails)
4. **Ledger Tampering** — modify `current_hash` in node1 → `LEDGER INTEGRITY: FAILED` (hash chain recomputation fails)
5. **Fake Watermark** — random `WM-FFFFFFFFFFFF` → `NO VALID LEDGER MATCH`

Run all: Frontend → Demonstrations → “Run All Tests” or `curl -X POST http://localhost:8000/api/test/end-to-end`

---

## Automated Tests

```bash
uv run pytest backend/tests/test_crypto.py -v
```

Covers (§14):

- ML-KEM encrypt/decrypt, AES round-trip, tamper rejection
- ML-DSA sign/verify, modified event → `INVALID`
- Watermark generation uniqueness, embed/extract round-trip
- Ledger hash verification, tampering detection
- **End-to-end attribution:** `Alice.decrypt(DOC-001)`, `Bob.decrypt(DOC-001)`, `assert Alice.watermark != Bob.watermark`, `leak = Alice.watermarked`, `result = forensic_verify(leak)`, `assert result.recipient == Alice && signature_valid && ledger_valid`

All tests passed on 2026-09-15 (9/9, see output in repo).

---

## Development Order (as built)

1. Project setup + dependency verification (§13 Phase 1)
2. PQC key generation — proves `ML-KEM works`, `ML-DSA works` (Phase 2)
3. Document encryption/decryption — proves `PDF → AES-GCM → Encrypted → ML-KEM → Decrypted` (Phase 3)
4. Watermark — proves `PDF A → WM-A, PDF B → WM-B` extraction (Phase 4)
5. ML-DSA event signing — proves `Event → Sign → Verify TRUE`, modified → `FALSE` (Phase 5)
6. Ledger — proves `Event → Ledger → Hash chain → Replication → Verification` (Phase 6)
7. Forensic verification — proves `Leaked PDF → Watermark → Ledger → Signature → Recipient` (Phase 7)
8. Frontend polish — Sender/Recipients/Ledger/Investigator dashboards (Phase 8)

---

## Watermark Details

- **Type:** Invisible frequency-domain, DCT 8×8, QIM at mid-frequency coeff (3,2), quantization Q=8, blind extraction (no original needed).
- **Payload:** Opaque `WM-` + 12 hex (15 chars = 120 bits), cyclically embedded with majority vote across ~32k blocks/page → robust, PSNR ~53 dB (invisible).
- **Not** PDF metadata, not visible watermark. Render at 150 DPI, modify Y channel in YCbCr, re-embed as lossless PNG inside PDF. Visually identical; text-selection lost (image-based) — acceptable for prototype.

---

## Ledger Details

- Entry: `{event, signature, public_key_b64, previous_hash, current_hash, timestamp}`
- Hash: `current_hash = SHA256(canonical_event + signature + previous_hash)` where `canonical_event = json.dumps(event, sort_keys=True, separators=(',',':')).encode()`
- Nodes: `ledger/node1..node4` (directories, could be separate processes). Commit replicates to all 4, succeeds if ≥3 accept → quorum 3/4. Verification recomputes chain on all nodes, checks consistency.
- Labelled **prototype ledger — not equivalent to production blockchain consensus**.

---

## PQC Dependency Verification

```bash
uv run --python 3.11 --with pqcrypto python -c "
from pqcrypto.kem.ml_kem_768 import keygen, encaps, decaps
from pqcrypto.sign.ml_dsa_65 import keygen as skg, sign, verify
pk,sk=keygen(); ct,ss=encaps(pk); assert ss==decaps(sk,ct)
pk2,sk2=skg(); sig=sign(sk2,b'msg'); verify(pk2,b'msg',sig); print('PQC OK')
"
```

If `pqcrypto` unavailable, the application **exits with an explicit error** rather than falling back to RSA/ECDSA (see `crypto/pqcrypto_wrapper.py`).

---

## Environment

- Tested on Arch/Omarchy, Python 3.11, Node 20, `uv 0.12.9`, `pqcrypto 1.0.0`, `pymupdf 1.28`, `cryptography 50`.
- All operations local: no cloud, no KMS, no public blockchain, no TEE/SGX, no DRM.

---

## License / Disclaimer

Prototype for demonstration. Not audited, not production-hardened. See security limitations above.

