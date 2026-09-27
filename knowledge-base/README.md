# BOUND — Knowledge Base

> **Project:** BOUND — Offline Post-Quantum Forensic Document Attribution
> **Problem Statement:** *Offline Post-Quantum Forensic Document Attribution* (SIH 2026, IDEA / internal hackathon)
> **Repo:** `PS/v1` (`git@github.com:anonatul/BOUND.git`)
> **Status:** Living knowledge base
> **Version:** 1.0
> **Last Updated:** 2026-09-27

This folder is the single source of truth for the team: what the problem is, what the
prototype actually does, how it is built, what is proven, what is *not* proven, and how to
demo and defend it in front of judges.

It is intentionally **honest**. Every strong claim is tagged with a status label so nobody
over-pitches it.

---

## How to use this KB

1. New teammate? Read `00` → `01` → `02` → `06` → `10`.
2. Building? Read `10` → `11` → `12` → `13` → `15`.
3. Pitching? Read `22` → `23` → `24`.
4. Judged? Read `17` → `18` → `25` → `23`.
5. Stuck? Read `20` → `21` → `30`.

---

## Status labels

Use these labels on every factual claim, exactly like the NETRA KB:

| Label | Meaning |
|---|---|
| ✅ **VALIDATED** | Proven by code + a passing test or a reproducible run. |
| 🟡 **ASSUMPTION** | Reasonable, not yet proven. |
| 🔵 **UNVERIFIED** | Needs external research / a real-world run. |
| 🔴 **REJECTED** | Must not be claimed as fact. |
| 🟣 **DECISION** | A deliberate engineering choice. |
| 🧪 **EXPERIMENT** | Being tested right now. |

---

## Index

| # | Document | What it answers |
|---|---|---|
| 00 | [Project Identity](00.%20Project%20Identity.md) | What BOUND is, one-liner, mission, positioning |
| 01 | [Problem Understanding](01.%20Problem%20Understanding.md) | Why document leak attribution is hard |
| 02 | [Problem Statement Decoded](02.%20Problem%20Statement%20Decoded.md) | Requirement-by-requirement decode of the PS |
| 03 | [Stakeholders & Users](03.%20Stakeholders%20%26%20Users.md) | Who uses it and what they need |
| 04 | [Existing Ecosystem & Prior Art](04.%20Existing%20Ecosystem%20%26%20Prior%20Art.md) | Logs, static watermarks, DRM, DLT, PQC products |
| 05 | [Validated Differentiation](05.%20Validated%20Differentiation.md) | What is genuinely novel vs. standard |
| 06 | [Product Definition](06.%20Product%20Definition.md) | The product, its objects and guarantees |
| 07 | [Core Workflow](07.%20Core%20Workflow.md) | End-to-end encrypt → decrypt → leak → attribute |
| 08 | [Functional Requirements](08.%20Functional%20Requirements.md) | FR list mapped to code |
| 09 | [Non-Functional Requirements](09.%20Non-Functional%20Requirements.md) | Offline, performance, size, security, NFRs |
| 10 | [System Architecture](10.%20System%20Architecture.md) | Components, layers, module map |
| 11 | [Cryptography Architecture](11.%20Cryptography%20Architecture.md) | ML-KEM/ML-DSA/AES-GCM/scrypt in detail |
| 12 | [Watermarking Deep Dive](12.%20Watermarking%20Deep%20Dive.md) | DCT QIM, zero-width markers, per-format matrix |
| 13 | [Ledger & DLT Architecture](13.%20Ledger%20%26%20DLT%20Architecture.md) | Signed nodes, Merkle checkpoints, quorum, LAN |
| 14 | [Data Architecture](14.%20Data%20Architecture.md) | Files, JSON schemas, storage layout |
| 15 | [API Reference](15.%20API%20Reference.md) | Every HTTP endpoint + ledger node API |
| 16 | [Frontend Architecture](16.%20Frontend%20Architecture.md) | React app, pages, components |
| 17 | [Security Model & Threat Model](17.%20Security%20Model%20%26%20Threat%20Model.md) | Adversaries, what holds, what does not |
| 18 | [Limitations & Failure Modes](18.%20Limitations%20%26%20Failure%20Modes.md) | Honest boundaries of the prototype |
| 19 | [Testing & Evidence](19.%20Testing%20%26%20Evidence.md) | 110 tests, what each proves |
| 20 | [Setup & Deployment Runbook](20.%20Setup%20%26%20Deployment%20Runbook.md) | Local, Docker, frontend |
| 21 | [LAN / Air-Gapped Deployment](21.%20LAN%20%26%20Air-Gapped%20Deployment.md) | Multi-device witness mode |
| 22 | [Demo Strategy](22.%20Demo%20Strategy.md) | The 5-minute judge demo |
| 23 | [Judge Cross-Examination](23.%20Judge%20Cross-Examination.md) | Hard questions + safe answers |
| 24 | [Metrics & Evidence](24.%20Metrics%20%26%20Evidence.md) | Measured numbers and how to reproduce |
| 25 | [Assumptions & Risks](25.%20Assumptions%20%26%20Risks.md) | Open assumptions and risk register |
| 26 | [Rejected Ideas](26.%20Rejected%20Ideas.md) | Alternatives considered and why dropped |
| 27 | [Research Sources](27.%20Research%20Sources.md) | Standards, papers, tools |
| 28 | [Journey & Decision Log](28.%20Journey%20%26%20Decision%20Log.md) | Git history + design decisions |
| 29 | [Glossary](29.%20Glossary.md) | Terms and acronyms |
| 30 | [FAQ & Troubleshooting](30.%20FAQ%20%26%20Troubleshooting.md) | Common failures and fixes |

---

## The 10-second summary

> **We do not try to stop a trusted recipient from leaking a document. We make every
> decryption produce a unique, invisible, session-specific forensic fingerprint, sign that
> decryption event with a post-quantum key, and record it in an offline multi-node signed
> ledger. When a copy leaks, the fingerprint is extracted and matched to the signed record
> to attribute the leak to a recipient and an exact session.**

```text
Encrypt once → decrypt individually → fingerprint each session → sign → offline DLT
             → investigate the leaked copy → verify → attribute
```

## The one demo that matters

> Two people receive the same document. Both copies look identical. Their forensic
> fingerprints are different. Leak one copy → the system correctly names the recipient and
> session. Then tamper with the audit record → verification fails.

✅ **VALIDATED** — this exact flow is covered by `backend/tests/test_crypto.py::test_complete_end_to_end_attribution`
and `test_api_integration.py`, and is exposed as the `/api/test/end-to-end` demo endpoint.
