# AI SOC — Standee Design Prompt (2.5 ft × 5 ft)

## Canvas Specifications

- **Size:** 30" × 60" (2.5 ft × 5 ft), portrait orientation
- **Resolution:** 300 DPI
- **Color mode:** CMYK

---

## Visual Identity

**Theme:** Dark cybersecurity aesthetic.

| Token | Value |
|---|---|
| Background | Deep navy `#0A0E1A` → near-black `#050810` gradient (top to bottom) |
| Primary accent | Electric cyan `#00D4FF` |
| Secondary accent | Neon green `#00FF88` |
| Alert / highlight | Amber `#FF8C00` |
| Heading text | White `#FFFFFF` |
| Body text | Light gray `#B0BEC5` |
| Card backgrounds | Semi-transparent dark blue `#0D1B2A` with subtle cyan border glow |
| Dividers | Thin cyan gradient lines between sections |
| Texture | Subtle hex-grid or circuit-trace pattern overlay at 5–8% opacity |

---

## Section 1 — Header (top ~15% of poster)

- **Top-left corner:** UIT University logo (high-res, white/transparent version)
- **Top-right corner:** Department of Computer Science logo

**Centered, stacked vertically:**

```
AI SOC
[~100 pt, bold, white, letter-spaced]

Autonomous Multi-Agent Security Operations Centre
[~44 pt, cyan, italic]

────────────────── cyan divider ──────────────────

Syed Abdul Munim Ul Hasan  ·  Hamza Ahmed Siddiqui
Huzaifa Shahid  ·  Syed Ali Raza
[~36 pt, white]

Supervised by: Engr. Fauzan Saeed (Assistant Professor)  |  Jawwad Bhutta (Senior Lecturer)
[~30 pt, light gray]

Department of Computer Science — UIT University
[~28 pt, light gray]
```

---

## Section 2 — Problem Statement & Motivation (CLO 1)

**~8% of poster height**

**Heading (~60 pt, cyan):** The Problem

**Body (~40 pt, light gray):**

Modern enterprises generate **millions of security alerts daily.** Human analysts cannot keep pace — alert fatigue leads to missed threats, slow response, and costly breaches. Traditional SOCs rely on manual triage, rule-based SIEM tools, and siloed threat intelligence — unable to adapt to the speed of modern cyberattacks.

> **Callout box (amber accent):** Global cybercrime costs projected to exceed $10.5 trillion annually by 2025. Enterprise SOCs receive 1,000–10,000 alerts/day — up to 45% are false positives.

---

## Section 3 — Objectives (CLO 2)

**~7% of poster height**

**Heading (~60 pt, cyan):** What We Built

Three icon-bullet rows (shield / brain / human-check icons in cyan):

- **Automate** end-to-end alert triage, enrichment, and response at machine speed
- **Augment** analyst decision-making with LLM-generated playbooks and RAG-retrieved threat context
- **Preserve** Human-in-the-Loop control for high-stakes or low-confidence decisions

---

## Section 4 — System Architecture (CLO 3)

**~25% of poster height — the visual centrepiece**

**Heading (~60 pt, cyan):** How It Works

Render a clean dark-mode architecture flow diagram with the following nodes connected by glowing cyan arrows:

```
[WAZUH SIEM]
    ↓ REST API polling
[APACHE KAFKA]  ← 24 partitions, 500 EPS
    ↓ 8 parallel workers
[LANGGRAPH PIPELINE]
  ├─ Log Analysis Agent  →  [REDIS cache/dedup]
  ├─ Threat Intel Agent  →  [MISP · VT · OTX · Shodan · NVD · MITRE]
  ├─ Playbook Gen Agent  →  [ChromaDB RAG]
  ├─ Supervisor          →  confidence ≥ 0.85?
  │     ├─ YES → [SOAR Agent] → [Shuffle SOAR]  ← green glow path
  │     └─ NO  → [HITL Agent] → [Analyst Review] ← amber glow path
                                      ↓
                              Approve / Edit / Reject
    ↓
[PostgreSQL audit log]   [FastAPI + Electron Dashboard]
```

**Diagram style:** Dark panel cards per node, cyan connecting arrows with small directional chevrons, green glow on the automated path, amber glow on the HITL path. Label each arrow with the action name.

**Below diagram — two-column spec block (~38 pt):**

| | |
|---|---|
| LLM | Meta-Llama-3.3-70B (local vLLM, air-gapped) |
| Vector Store | ChromaDB + all-MiniLM-L6-v2 |
| Broker | Apache Kafka 3.7 KRaft |
| SIEM | Wazuh 4.10.2 |

---

## Section 5 — Key Features (CLO 5)

**~15% of poster height | 2×3 card grid**

**Heading (~60 pt, cyan):** Key Features

Six dark-panel cards, each with a cyan icon + label + one-line description (~36 pt):

| Icon | Label | Description |
|---|---|---|
| Shield | Alert Triage | LLM + rule-based severity classification with IOC extraction |
| Globe | Threat Intel Enrichment | 6-source intel fusion: MISP, VirusTotal, OTX, Shodan, NVD, MITRE ATT&CK |
| Book | RAG Playbooks | Retrieval-Augmented Generation from NIST CSF, ATT&CK, past incidents |
| Person-Check | HITL Oversight | PostgreSQL LISTEN/NOTIFY real-time analyst review queue |
| Bolt | SOAR Execution | Shuffle workflow automation for one-click or autonomous response |
| Monitor | Electron Dashboard | Real-time SIEM + SOAR + HITL queue in a cross-platform desktop UI |

---

## Section 6 — Results & Evaluation (CLO 6)

**~10% of poster height**

**Heading (~60 pt, cyan):** Results

Three large metric cards side by side with glowing numbers:

```
┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│   500 EPS      │   │  Air-Gap Ready │   │  6 TI Sources  │
│  [cyan ~80pt]  │   │  [green ~80pt] │   │  [cyan ~80pt]  │
│ Peak throughput│   │ Zero internet  │   │  Fused in real │
│   sustained    │   │   at runtime   │   │  time per alert│
└────────────────┘   └────────────────┘   └────────────────┘
```

Below the cards: a horizontal pipeline flow showing per-stage processing with approximate latency labels (mark as "indicative" if exact numbers are unavailable).

---

## Section 7 — Conclusion & Future Work (PLO 12)

**~8% of poster height | two columns**

**Heading (~60 pt, cyan):** Conclusion & Future Work

**Left column — What we achieved (~38 pt):**
- Proved LLMs can autonomously classify and respond to real-world security alerts
- Fully air-gapped deployment: no runtime internet dependency
- HITL oversight maintains analyst accountability at critical decision points

**Right column — What's next (~38 pt):**
- Federated threat-intel sharing across isolated SOC nodes
- Adversarial robustness against prompt-injection attacks on the LLM pipeline
- Mobile analyst interface for on-call HITL approvals

---

## Section 8 — Footer (mandatory)

**~7% of poster height | horizontal band with slightly lighter dark background**

**Left — SDG Badges:**
- SDG 9 icon + label: *Industry, Innovation & Infrastructure*
- SDG 16 icon + label: *Peace, Justice & Strong Institutions*

**Centre — Acknowledgments (~28 pt, light gray):**
> We thank Engr. Fauzan Saeed and Jawwad Bhutta for their guidance, and the UIT Department of Computer Science for support throughout this project.

**Right — References (~24 pt, light gray):**
1. LangChain / LangGraph — langchain.com
2. Wazuh SIEM — wazuh.com
3. MITRE ATT&CK — attack.mitre.org
4. Shuffle SOAR — shuffler.io

*(Optional: QR code linking to demo video or GitHub repo)*

---

## Typography

| Element | Font | Size |
|---|---|---|
| Main title | Inter ExtraBold or Montserrat Black | 100 pt |
| Section headings | Inter Bold | 60–80 pt |
| Card labels | Inter SemiBold | 44 pt |
| Body text | Inter Regular | 38–42 pt |
| Footer / references | Inter Light | 24–28 pt |

---

## Designer Checklist

- [ ] Canvas: 30" × 60", 300 DPI, CMYK
- [ ] UIT logo + Dept logo in top corners (high-res, white/transparent versions)
- [ ] No white background — deep navy throughout
- [ ] Architecture diagram is the largest single visual element
- [ ] All body text ≥ 38 pt (readable at arm's length)
- [ ] SDG 9 + SDG 16 badges present in footer
- [ ] Word count under 800–1000 words total
- [ ] ~60% visuals, ~40% text ratio
- [ ] Export: PDF (print-ready) + PNG (preview)
