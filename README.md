# BOUND — Offline Post-Quantum Forensic Document Attribution

A working prototype of broadcast-encrypt / individually-decrypt document distribution where every decrypted copy carries a unique, invisible forensic watermark bound to the recipient's session and to their own post-quantum signing key, and every decryption event is committed to a tamper-evident multi-node ledger.

Real post-quantum cryptography (ML-KEM-768, ML-DSA-65), real AES-256-GCM, real per-format forensic watermarking, real per-node signatures, and a real 3-of-4 quorum. Runs fully offline; no cloud, no KMS, no public blockchain.

> **Prototype, not production security.** See [Security Model & Honest Limitations](#security-model--honest-limitations).

---

## What Changed in v2

| Area | v1 | v2 / v2.1 |
|---|---|---|
| Output file size | 124 KB source became 44-115 MB (full-page PNG raster) | Preserve mode: a 3 KB source PDF produces a ~2.6 KB watermarked copy |
| Output fidelity | Image-only pages, text no longer selectable | Original PDF is preserved: vector text stays selectable and searchable; only embedded raster images are re-encoded |
| Watermark ID | `WM-` + 12 hex = 48 bits entropy | `WM-` + 26 base32 chars = 128 bits entropy |
| Watermark channels | DCT only | Invisible PDF text layer (exact recovery) + DCT QIM on embedded images with CRC32 and 5x repetition; optional `rasterize` mode for full-page DCT robustness |
| File formats | PDF only | PDF, images (PNG/JPEG/BMP/TIFF/WebP), text-like files (txt/md/log/ini/cfg/CSV/TSV/JSON/YAML/XML/HTML), Office OOXML (docx/xlsx/pptx), and a generic ZIP container fallback for everything else |
| Identity | Hardcoded ALICE/BOB, plaintext keys, no auth | Accounts with passphrase-protected private keys (scrypt + AES-256-GCM), session tokens, unlock flow, dynamic user registry |
| Ledger | 4 JSONL files written by one process, "quorum" nominal | Each node has its own ML-DSA keypair and signs every entry and Merkle checkpoint; client verifies a real 3-of-4 node quorum |
| Admin tampering | Recompute hashes on 4 files and pass | Consistent rewrite of all node files is rejected: node signatures cannot be forged without node keys |
| Attribution resilience | Any single node tamper broke attribution | Attribution survives one corrupt/tampered node (`verify_entry_quorum`) |
| Frontend | Crypto dashboard with Alice/Bob tabs | Minimal file-sharing app: Files, Shared with me, People, Verify, Audit (+ secondary Security demos), with global search, sortable/filterable tables, detail drawers, and passphrase show/hide |

---

## Architecture

```
Sender (authenticated)
  → AES-256-GCM encrypt document once
  → ML-KEM-768 encapsulate per authorized recipient (wrapped AES key)
  → store ciphertext + wrapped keys

Recipient (authenticated, keys unlocked)
  → ML-KEM-768 decapsulate → AES-256-GCM decrypt
  → fresh session ID + nonce
  → 128-bit watermark ID  WM- + base32(SHA-256(doc_hash|recipient|session|nonce))
  → format dispatcher picks a handler by extension + magic-byte sniffing:
    PDF (invisible text + DCT QIM) | image (Y-channel DCT QIM)
    | text-like and OOXML (zero-width marker) | ZIP container fallback
  → sign canonical decryption event with recipient's ML-DSA-65 private key
  → commit to 4 ledger nodes; each node ML-DSA-signs the entry
    and appends a signed Merkle checkpoint (quorum 3/4)

Investigator
  → upload leaked file (any supported type)
  → extract watermark (extension/sniff → native handler
    → container fallback; CRC/regex validated at every step)
  → ledger lookup by watermark ID
  → verify recipient ML-DSA signature
  → verify entry is validly signed on >= 3 of 4 nodes
  → verify strict full-chain integrity and Merkle checkpoints
  → return a cryptographically verifiable attribution record
```

---

## Requirement Mapping

| Requirement | Implementation | Status |
|---|---|---|
| Unique invisible watermark at decryption time | `services/decryption_service.py`, `watermark/dct_watermark.py` | Met |
| Per recipient and session | session + nonce + recipient in watermark derivation | Met |
| Visually identical, forensically distinct | PSNR ~41 dB on the PDF sample, >30 dB in image tests, per-session IDs | Met on PDF and image artifacts |
| Cryptographically bound to recipient identity | ML-DSA-65 signature over canonical event | Met, with caveat below |
| Recipient's own private key | Per-user keypair; passphrase-encrypted at rest; must be unlocked (or passphrase supplied) to sign | Partial: keys are held server-side in this prototype |
| NIST PQC for KEX and signatures | ML-KEM-768 + ML-DSA-65 via `pqcrypto` (real, fails loudly if missing) | Met |
| Immutable audit layer (blockchain/DLT) | Append-only hash chain, 4 independently signed nodes, Merkle checkpoints, 3/4 quorum | Met in the tamper-evidence sense; not a consensus network |
| No single admin can alter/delete records | Admin with file access but no node keys cannot forge history (demonstrated) | Partial: node keys are colocated in this prototype |
| Extract watermark from leaked copy | Format dispatcher: native channel per type, ZIP container comment fallback, CRC/regex validated | Met |
| Ledger lookup | `find_by_watermark`, `verify_entry_quorum` | Met |
| Verifiable record identifying recipient | signature + per-node quorum + chain evidence | Met |
| Offline / air-gapped | All operations local; no network calls | Met |
| No cloud KMS | Keys are local files / local scrypt derivation | Met |
| No public blockchain | Local ledger nodes only | Met |

---

## Project Structure

```
BOUND/
├── backend/app/
│   ├── crypto/pqcrypto_wrapper.py      # ML-KEM / ML-DSA wrappers (real)
│   ├── identity/manager.py             # accounts, encrypted keys, unlock store
│   ├── auth/service.py                 # sessions, register/login/logout
│   ├── auth/deps.py                    # FastAPI bearer dependencies
│   ├── encryption/aes.py, document.py  # AES-GCM, per-recipient ML-KEM wrapping
│   ├── watermark/formats.py            # dispatcher: extension + magic sniff, container fallback
│   ├── watermark/handlers/             # common.py, image.py, text.py, container.py, ooxml.py
│   ├── watermark/dct_watermark.py      # 128-bit ID, invisible PDF text + DCT QIM
│   ├── ledger/ledger.py                # signed nodes, Merkle checkpoints, quorum
│   ├── forensic/events.py, verify.py   # canonical events, signing, forensic pipeline
│   ├── services/decryption_service.py  # full recipient decrypt/watermark/sign/commit
│   └── main.py                         # FastAPI app (auth, files, verify, demos)
├── backend/keys/                       # per-user public registry + encrypted private keys
├── backend/tests/                      # crypto, watermark (v2, formats, OOXML), ledger, auth, API
├── frontend/src/                       # minimal React app (Login, Files, Shared, People, Verify, Audit, Demo)
│   ├── services/fileTypes.js           # format labels (pdf | image | text | ooxml | container)
│   └── components/FileTypeBadge.jsx    # per-file type badge
├── ledger/node1..4/                    # ledger.jsonl, checkpoints.jsonl, node ML-DSA keys
├── storage/encrypted/, watermarked/    # runtime artifacts (gitignored)
├── documents/demo-secret.pdf           # generated 3-page sample
├── Dockerfile, docker-compose.yml, pyproject.toml
```

---

## Quick Start

### Backend + built frontend

```bash
uv sync --python 3.11
uv run uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
# App:  http://localhost:8000
# Docs: http://localhost:8000/docs
```

### Frontend development

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173 (proxies /api to :8000)
npm run build    # production build served by FastAPI
```

### Docker

```bash
docker compose up --build
```

---

## Using the App

1. **Sign in.** Demo accounts: `ALICE` / `demo12345`, `BOB` / `demo12345`. Or create an account (username 3-24 chars `A-Z0-9_`, passphrase >= 8 chars); new accounts get passphrase-encrypted private keys. The form checks username availability live and lets you reveal the passphrase while typing.
2. **Files.** Upload any file type, pick recipients, share. Encryption is broadcast: one ciphertext, one ML-KEM-wrapped key per recipient. Rows show a type badge; PDFs, images, text-like files, and Office documents are watermarked natively, while other types are delivered in a forensic ZIP container. Search, filter, sort, and open any document to see its metadata and every recorded decryption session.
3. **Shared with me.** Decrypt a document you are authorized for. If your key is locked, the app prompts for your passphrase and unlocks for 30 minutes. You receive a copy watermarked to your session: a native watermarked file when the type is supported natively (PDFs keep selectable text), otherwise a forensic ZIP container.
4. **People.** Searchable directory of registered users with algorithm variants, public-key fingerprints, key-storage type, and document counts.
5. **Verify.** Upload a leaked copy of any supported type. The app detects the format (`pdf`, `image`, `text`, `ooxml`, or `container`), extracts the watermark, matches the ledger, verifies the recipient signature and node quorum, and names the accountable session, with links to the matching document and audit entry.
6. **Audit.** Ledger entries with per-entry quorum, per-node validity, checkpoints and Merkle root. Plain-language explanations are available inline. If a node is ever left divergent (for example after running the tampering demo while the page was open), the "Re-sync from quorum" button repairs it from the valid majority.
7. **Security demos** (secondary nav). Six runnable demonstrations, including consistent multi-node tampering by a privileged admin with file access but no node keys. The Audit view refreshes after each demo.

---

## API Overview

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/health` | - | Health + PQC/ledger info |
| `POST` | `/api/auth/register` | - | Create account with encrypted keys |
| `POST` | `/api/auth/login` | - | Verify passphrase, unlock keys, issue token |
| `POST` | `/api/auth/unlock` | Bearer | Re-unlock keys for 30 minutes |
| `POST` | `/api/auth/logout` | Bearer | Invalidate session |
| `POST` | `/api/auth/lock` | Bearer | Lock the session's in-memory private keys |
| `GET` | `/api/auth/me` | Bearer | Current user + unlock state |
| `GET` | `/api/auth/username-available` | - | Case-insensitive duplicate username check |
| `GET` | `/api/recipients` | - | Public registry with key fingerprints and document counts |
| `GET` | `/api/recipients/{id}` | - | Public profile for one recipient |
| `POST` | `/api/encrypt` | Bearer | Upload any file type with an extension + recipients, AES-GCM + ML-KEM wrapping |
| `GET` | `/api/documents` | Bearer | Documents where you are owner or recipient (`role`, decryption count) |
| `GET` | `/api/documents/{id}/events` | Bearer | All recorded decryption sessions for a document |
| `POST` | `/api/decrypt` | Bearer | Decrypt, watermark natively or wrap in a forensic ZIP, sign, commit, download URL |
| `GET` | `/api/watermarked/{file}` | token/session | Download a marked copy with its native extension, or `.zip` for container output (HMAC token, 10 min) |
| `GET` | `/api/ledger` | - | Entries with per-entry quorum, integrity, Merkle root, per-node checkpoints |
| `POST` | `/api/ledger/repair` | - | Re-sync divergent nodes from the valid 3/4 quorum chain |
| `POST` | `/api/verify` | optional | Forensic verification of a leaked file; returns `format` (`pdf`, `image`, `text`, `ooxml`, or `container`) |
| `POST` | `/api/test/*` | optional | Security demonstrations |

---

## Watermark Details

- **ID:** `WM-` + 26 RFC4648 base32 chars from a 128-bit SHA-256 digest of `document_hash|recipient_id|session_id|nonce`.
- **Dispatch:** embed and extract pick a handler by filename extension first and magic-byte sniffing second (`watermark/formats.py`); any handler that cannot embed safely hands the file to the ZIP container fallback.

**Per-format matrix**

| Kind | Types | Channel and payload | Output | Notes |
|---|---|---|---|---|
| PDF | `.pdf` | Invisible text layer (exact recovery) plus DCT QIM on embedded images; 29 ID bytes + CRC32, repetition 5, coefficient (3,2), Q=16 | Edited in place in `preserve` mode; embedded images re-encoded as JPEG q85, or PNG when the source was PNG/alpha | Preserve and rasterize behaviour described below |
| Image | `.png`, `.jpg` / `.jpeg`, `.bmp`, `.tif` / `.tiff`, `.webp` | Y-channel DCT QIM at coefficient (3,2), Q=16; payload 29 ID bytes + CRC32 with repetition 5 | Same-format re-encode: PNG/BMP/TIFF-LZW/WebP lossless, JPEG q90; alpha preserved | Animated and palette images, and images too small to carry the payload, fall back to the container |
| Text-like | `.txt`, `.md`, `.log`, `.ini`, `.cfg`, `.csv` / `.tsv`, `.json`, `.yaml` / `.yml`, `.xml` / `.html` | Zero-width Unicode marker (U+200B for 0, U+200C for 1, framed by U+2060 guards) carrying the 29 ID bytes + CRC32 | Marker inserted at a format-safe position: final line, end of the first header line, comment line, XML/HTML comment, or inside the first JSON string; visible content unchanged | Only applied to valid UTF-8 text |
| OOXML | `.docx`, `.xlsx`, `.pptx` | Same zero-width marker injected into the document text: `word/document.xml`, `xl/sharedStrings.xml` or the first worksheet, `ppt/slides/slide1.xml`, or `docProps/core.xml` | ZIP rebuilt losslessly, all other members copied byte-for-byte; visible document unchanged | Falls back to the container when no safe member exists |
| Fallback | everything else, and any handler that cannot embed safely | ZIP archive comment `BOUNDWM1:<watermark_id>` | Original bytes delivered inside a `.zip`, or the comment set on an existing archive | Only the wrapper is protected: if someone extracts the inner file and shares only that, the container watermark no longer travels with it |

- **Default mode `preserve`:** the original PDF is edited in place.
  - **Channel A (exact):** the ID is inserted as invisible text (`render_mode=3`) at multiple positions per page. The original text stays selectable and searchable; extraction is exact.
  - **Channel B (robust where images exist):** each embedded raster image with enough blocks is DCT-watermarked in place (payload = 29 ID bytes + CRC32, repetition 5, QIM at coefficient (3,2), Q=16) and re-encoded as JPEG q85 (or PNG when the source was PNG/alpha).
  - Measured on the included 3-page sample: source 2,969 B -> watermarked copy 2,632 B, PSNR is effectively infinite for text-only pages (rendering is byte-identical).
- **Optional mode `rasterize`:** rasterizes every page at 150 DPI as JPEG q85 and DCT-watermarks the full page. This survives re-rendering/printing pipelines at the cost of losing text selection. Use `embed_watermark(pdf, wm, mode="rasterize")`.
- **Extraction order:** extension/magic sniff -> native handler (PDF text, then per-image DCT, then full-page rendered DCT; image Y-channel DCT; text and OOXML zero-width markers) -> ZIP container comment fallback. Every candidate is validated by CRC or the watermark-ID regex before it is accepted.
- Honest trade-off: in `preserve` mode, a leak that is flattened to a single image loses the text channel, and documents with no embedded images have no DCT channel. `rasterize` mode is the stronger forensic option for scanned image documents.
- Honest trade-off (container fallback): the watermark lives in the ZIP archive comment, so it protects the wrapper only. Extracting the inner file and sharing that alone leaves the container watermark behind.

## Ledger Details

- **Entry:** `{seq, event, signature (recipient), public_key_b64, previous_hash, current_hash, timestamp, node_id, node_signature, denormalized document/recipient/session/watermark ids}`.
- `current_hash = SHA256(canonical_event + recipient_signature + previous_hash)`.
- **Node signing:** each node holds its own ML-DSA-65 keypair (`ledger/nodeN/node_mldsa_*.b64`) and signs a canonical core of every entry. Node signatures differ per node for the same event. In `BOUND_LEDGER_MODE=lan` the keypair lives on a separate device and never leaves it.
- **Checkpoints:** every append also writes a signed checkpoint containing a binary Merkle root over all entry hashes (`checkpoints.jsonl`).
- **Quorum:** in local mode, at least 3 of 4 nodes; in LAN mode, a strict majority of registered member devices. Verification exposes `quorum`, `quorum_ok`, `merkle_root`, and `divergent_nodes`.
- **Attribution resilience:** `verify_entry_quorum(watermark_id)` proves the record exists identically on a valid quorum of nodes. An investigator can still attribute when one node is corrupted.
- **Admin tampering:** rewriting every node's files consistently and recomputing every hash still fails, because `node_signature` values cannot be forged without the node private keys. In LAN mode those keys are on separate devices, which is what makes the guarantee hold against a privileged coordinator.

---

## LAN / Air-Gapped Multi-Device Mode

By default the ledger is four directories written by one process (`BOUND_LEDGER_MODE=local`). Set `BOUND_LEDGER_MODE=lan` to spread the ledger across **whatever real devices you put on the isolated LAN**. There is no fixed node count and no IP list to edit: each device runs the node agent and **announces itself to the coordinator**, which adds it as a member.

```
        ISOLATED WIFI ROUTER (no Ethernet / WAN uplink)
   Coordinator (app+frontend) ◄── auto-join ── laptop B
           │                                  laptop C
           └── HTTP ── every member device runs one node agent
```

**Why it matters:** each node's ML-DSA private key is generated on and never leaves its own device, so a privileged admin with access to the coordinator (or to any single node) cannot forge a consistent rewrite of the whole chain.

### Quorum rule: a majority of members

The threshold depends on how many devices have joined, **not** on how many are online:

| Members | Quorum |
|---|---|
| 1 | 1 |
| 2 | 2 |
| 3 | 2 |
| 4 | 3 |
| 5 | 3 |
| 6 | 4 |

Because the threshold is fixed by membership, a coordinator that can knock nodes off the network cannot shrink the requirement and forge a record. A node going offline is reported unreachable; it is not silently dropped from the member list.

> With 2 devices, the split is 1 node each and quorum 2 — **both must be online** to record, and neither alone can forge. Add more laptops and the quorum scales automatically.

### 1. Network
- Router with no Ethernet/WAN cable; disable client/AP isolation so devices can talk to each other.
- Give each device a static IP (e.g. coordinator `192.168.50.10`). No DNS needed.

### 2. Start the coordinator
On the coordinator device:
```bash
export BOUND_LEDGER_MODE=lan
export BOUND_ENROLL_TOKEN="pick-a-shared-secret"   # optional: gates who may join
uv run uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

### 3. Start one node per witness device
On each other device, from the repo:
```bash
BOUND_NODE_ID=laptopB \
BOUND_NODE_PORT=9101 \
BOUND_COORDINATOR_URL=http://192.168.50.10:8000 \
BOUND_ENROLL_TOKEN="pick-a-shared-secret" \
./scripts/start_node.sh
```
On Windows PowerShell (keep each command on its own line; do **not** join them):
```powershell
cd $HOME\Documents\BOUND
.\scripts\start_node.ps1 -NodeId laptopB -Port 9101 -CoordinatorUrl http://192.168.50.10:8000
```
If the script gives trouble, run the node directly without it (same thing):
```powershell
$env:BOUND_NODE_ID = "laptopB"
$env:BOUND_NODE_PORT = "9101"
$env:BOUND_COORDINATOR_URL = "http://192.168.50.10:8000"
uv run uvicorn backend.app.ledger.node_agent:app --host 0.0.0.0 --port 9101
```
First start generates that node's keypair locally, then it announces itself and is added automatically. Confirm with `curl http://<device-ip>:9101/node/info` (only the **public** key is ever returned) and check membership with `curl http://192.168.50.10:8000/api/ledger/members`.

### 4. Use the app
Files, Shared with me, Verify and Audit are unchanged — the ledger layer switches transport transparently. The Audit view shows the live members, the required quorum, and any divergent node.

### Membership & Node API (plain HTTP on the isolated LAN)
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ledger/register` | a node announces itself (id, port, public key); the coordinator derives its URL from the observed source IP and adds it as a member |
| GET | `/api/ledger/members` | registered member devices + current quorum |
| DELETE | `/api/ledger/members/{id}` | remove a member |
| GET | `/health`, `/node/info` | node liveness; public key + chain head |
| GET | `/node/entries` | full chain (used for peer sync) |
| GET | `/node/find?watermark_id=` | entry + chain-prefix validity |
| POST | `/node/append` | coordinator proposes; node independently validates then signs |
| POST | `/node/verify` | node self-verifies chain + Merkle checkpoints |
| POST | `/node/sync` | adopt a peer's canonical chain, re-signing every entry locally |

A newly joined node is seeded with the existing chain automatically. The public key is pinned on first join: re-announcing with a different key is rejected.

### Failure behaviour
- **One node down (of 4+)** → the majority quorum still commits and attributes (`backend/tests/test_ledger_lan.py`).
- **A node edited on its device** → `verify_all_ledgers` flags it; `repair_divergent_nodes` re-syncs it peer-to-peer, re-signing locally (it is never overwritten from a trusted file copy).
- **Fewer than the quorum reachable** → commits refuse.

> Plain HTTP is intentional: the air-gapped router is the security boundary. For a stronger transport, terminate TLS locally with a self-signed CA.
>
> The local-only "tampering" demo endpoints return `skipped` in LAN mode, because the nodes live on separate devices; tamper with a node there and the Audit view flags it.

---

## Automated Tests

```bash
uv run pytest backend/tests -q
```

- `test_crypto.py` — ML-KEM, AES-GCM, ML-DSA, watermark round trip, ledger hash chain, end-to-end attribution.
- `test_watermark_v2.py` — ID format/entropy, preserve-mode text selectability, size and PSNR bounds, image DCT channel, rasterize-mode fallback.
- `test_watermark_formats.py` — dispatcher routing by extension and magic bytes, image DCT round trips per format (PSNR, alpha), zero-width text round trips for each supported type, container fallback for unknown and unsafe inputs, output naming helpers.
- `test_watermark_ooxml.py` — docx/xlsx/pptx zero-width round trips, visible text and untouched members preserved, CRC rejection, and error paths for unreadable archives.
- `test_ledger_v2.py` — per-node signatures, checkpoints, single-node tamper vs. all-node consistent tamper, quorum.
- `test_auth.py` — registration, encrypted keys, wrong passphrase, unlock, sessions, legacy demo users.
- `test_api_integration.py` — full HTTP flow: username availability, register/login, encrypt, role-filtered documents, document events, locked-decrypt 403, unlock, decrypt, signed download, ledger repair from quorum, admin-tamper demo, forensic verify, logout — including multi-format upload, decrypt, and verify coverage.
- `test_ledger_lan.py` — spins four real node-agent processes on localhost and exercises LAN mode: commit + full verification, per-entry majority quorum, divergence detection, and peer-to-peer repair with local re-signing.
- `test_members.py` — dynamic membership: strict-majority quorum table, add/list/remove, public-key pinning, and URL refresh on re-announce.

---

## Security Model & Honest Limitations

**Threat model that the prototype addresses:** a privileged operator or compromised server account tries to alter or delete the audit record; a recipient leaks a copy and denies it; an investigator must identify the source from an artifact.

**What is real:** PQC KEM and signatures, AES-GCM, per-node independent signing, Merkle checkpoints, quorum verification, passphrase-protected keys at rest, session auth, watermarks that differ per session.

**Known limitations (must be stated honestly):**

- In the default `local` mode the four node private keys sit next to the ledger files; an attacker with both file access and those key files can still forge. Run `BOUND_LEDGER_MODE=lan` (see below) so each node's key is generated on and stays on its own device — that is the configuration intended to satisfy the "no single administrator" requirement. Production would add HSMs / independent host permissions.
- For encrypted accounts, private keys are held by the server process after unlock. The signature is produced server-side on the recipient's behalf, which weakens true non-repudiation. Full non-repudiation requires client-side signing (liboqs/WASM in the browser or a local key agent) or a hardware token.
- The two demo accounts (ALICE/BOB) keep legacy plaintext keys for compatibility with the demo flows. New accounts use encrypted keys.
- Watermarking does not survive print/scan, photography, screenshot with re-typing, or deliberate removal. In the default `preserve` mode it survives normal PDF copies and re-saves (invisible text channel) and JPEG re-encoding of embedded images (DCT channel); a leak flattened to a single bare image loses the text channel. Use `mode="rasterize"` when full-page DCT robustness matters more than text selection.
- Per-format caveats: text-like zero-width markers can be stripped by rewriting the text (editors or pipelines that drop zero-width characters); OOXML markers survive normal Office editing but not deliberate removal; image DCT channels degrade under aggressive rescaling or repeated recompression; and the ZIP container fallback only protects the wrapper, so an inner file extracted and shared alone no longer carries the watermark.
- Removing the visible/invisible text layer does not remove the original document text; the trade-off is described above.
- The ledger is a replicated signed data structure, not a Byzantine-fault-tolerant consensus network. It is honest about its trust assumptions.
- Everything is prototype-grade: no fuzzing, no formal audit, no rate limiting, single-process SQLite-free file storage.

---

## Environment

- Python 3.11 (uv), Node 20+ for the frontend.
- Tested with `pqcrypto`, `cryptography`, `pymupdf`, `numpy`, `scipy`, `reportlab`, `Pillow`, FastAPI.
- Fully local: no cloud, no KMS, no public blockchain, no TEE, no DRM.
