# EU Cyber Resilience Act (CRA) Audit Pipeline

An enterprise-grade, multi-agent compliance validation platform engineered to programmatically audit software applications against the statutory conformity demands of **CRA Article 10**. Powered by **LangGraph**, the pipeline orchestrates specialized AI agents to extract dependencies, query the live **National Vulnerability Database (NVD)** API, evaluate security postures against regulatory criteria, and deliver real-time compliance verdicts.

---

## 🎯 System Architecture Overview

The pipeline breaks away from brittle, monolithic script scanners by treating compliance auditing as a dynamic multi-agent coordination problem. Using a state-driven graph topology, data flows sequentially through strictly sandboxed processing nodes:

```text
       [ START ]
           │
           ▼
┌──────────────────────┐
│  SBOM Generator      │ ──► Parses Python, Java, & C++ Manifests
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│ Vulnerability Scan   │ ──► Queries Live NVD API via Throttled Session
└──────────────────────┘
           │
           ▼
┌──────────────────────┐
│  CRA Auditor Node    │ ──► Evaluates CVSS Risk & CRA Article 10 Criteria
└──────────────────────┘
           │
           ▼
        [ END ]  ──► Emits Conformity Certificate (PASS/FAIL)
```

### Core Agent Nodes
1. **SBOM Generator Agent**: Scans target workspaces for multi-language package roots. It utilizes structural parsing (such as `xml.etree.ElementTree` for Java `pom.xml` configurations) to extract clear component metadata arrays.
2. **Live Vulnerability Scanner Agent**: Executes parallel queries against NIST's live NVD registry using an encrypted API layer. Employs connection pooling and predictive exponential backoff loops to gracefully handle rate limit throttling.
3. **CRA Compliance Auditor Agent**: Serves as the final regulatory arbiter. Evaluates discovered CVE vectors against strict EU risk rules, automatically issuing a blocking fail state if any unmitigated High or Critical vulnerabilities (CVSS ≥ 7.0) are found.

---

## ✨ Advanced Engineering Highlights

* **Concurrent Sandbox Isolation**: Combines Streamlit session states with dynamic UUID token generation to spin up completely independent workspace directories per active visitor. This architecture blocks cross-user data contamination and protects system memory boundaries during multi-file evaluation runs.
* **PEP 440 Version Normalization**: Features regex-driven sanitization logic that forces non-standard legacy and vendor version signatures (e.g., `OpenSSL 1.0.1f`) into valid numeric components to ensure flawless comparison against complex NVD vulnerability boundaries (`versionStart`/`versionEnd`).
* **XSS-Safe Security Visualizer**: Leverages explicit Markdown text compilation streams to inject immediate behavioral telemetry and visual alert icons across threat cards, entirely dodging the use of unsafe raw HTML rendering blocks.

---

## 📂 Core Directory Structure

```text
├── app.py               # Production Streamlit UI & Workspace Sandbox Router
├── main.py              # Mock Environment CLI Local Verification Script
├── pipeline.py          # LangGraph State Graph Workflow Compilation Core
├── agents.py            # Implementation Logic for Autonomous Agent Nodes
├── schemas.py           # Pydantic v2 Data Transfer Schemes & State Types
├── config.py            # Production-Ready Environment Variable Resolution Engine
└── requirements.txt     # Strict Production Package Pin Constraints
```

---

## 🚀 Quickstart & Local Installation

### 1. Clone the Codebase
```bash
git clone https://github.com](https://github.com/smruti1979/eu-cra-audit-pipeline.git
cd eu-cra-audit-pipeline
```

### 2. Configure Environment Settings
Create a `.env` configuration file inside your project root to pass your NIST API credentials locally:
```text
NVD_API_KEY=your_secured_nvd_api_token_here
NVD_BASE_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
```

### 3. Initialize Virtual Environment & Install Dependencies
```bash
python -u -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Run CLI Integration Tests
Execute the local CLI runner to spin up a mock polyglot codebase containing intentional high-risk legacy vulnerabilities (such as `Log4j 2.14.1` and `OpenSSL 1.0.1f`) to confirm agent execution paths:
```bash
python main.py
```

### 5. Launch the Streamlit Platform Interface
```bash
streamlit run app.py
```

---

## 🛡️ Regulatory Compliance Context: CRA Article 10

The **EU Cyber Resilience Act (CRA)** imposes mandatory, legally binding cyber security standards for all digital products entering the European Union market. 

* **The Mandate**: Manufacturers must deliver products free of known, actively exploitable vulnerabilities.
* **The Enforcement**: This pipeline programmatically checks software packages against standard security vectors. Components carrying a **CVSS Score $\ge$ 7.0** are flagged instantly, blocking compliance issuance and protecting organizations from severe regulatory enforcement actions.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
