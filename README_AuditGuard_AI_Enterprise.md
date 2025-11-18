# 🛡️ AuditGuard AI — IAM Audit Readiness (Enterprise Demo)

[![Launch in Streamlit](https://img.shields.io/badge/Launch%20Dashboard-🛡️%20Streamlit-black?style=for-the-badge&logo=streamlit)](https://auditguard-ai.streamlit.app/)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-UI%20Dashboard-orange)
![Compliance](https://img.shields.io/badge/Frameworks-NIST%20800--53%20%7C%20ISO%2027001%20%7C%20PCI%20DSS%20%7C%20SOC%202-green)

**AuditGuard AI** unifies identity data (Salesforce, AWS IAM, Azure Entra ID, and more) to surface access risks, map findings to industry frameworks, and export evidence for audits.  
Built for **enterprise demos, presales, and investor conversations** — fast to run, easy to extend.

---

## ✨ What’s Inside

- **Multi-source normalization** — Upload exports from Salesforce, AWS IAM, Azure Entra, or a generic CSV. AuditGuard standardizes fields automatically.  
- **Risk classification** — Flags MFA gaps, inactive users, stale credentials, orphaned accounts, and excessive roles.  
- **Framework mapping** — Aligns each finding to **NIST 800-53, ISO 27001, PCI DSS, SOC 2** for immediate audit readiness.  
- **Enterprise dashboard** — KPIs, severity chart, filters by source/severity/framework, and table density toggle.  
- **One-click evidence** — Download an **Executive Summary (Markdown)** and **Findings CSV** for auditors or boards.  
- **Demo-ready** — “Load sample data” instantly populates realistic Salesforce, AWS, and Azure examples.

> Optional lab modules (RBAC simulation, incident timeline, GPT4All checks) live in a separate branch for R&D showcase.

---

## 🧭 Quickstart

### 1. Install dependencies
```bash
pip install streamlit pandas
# or: pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run AuditGuard_streamlit_app_enterprise.py
```

### 3. Load sample data
In the sidebar, click **“🔁 Load sample data (demo)”** to auto-populate cross-platform IAM exports.

---

## 📁 Repo Structure
```
.
├── AuditGuard_streamlit_app_enterprise.py   # Main Streamlit app (no matplotlib dependency)
├── README.md
├── requirements.txt                         # streamlit, pandas
└── samples/                                 # optional (sample IAM exports)
    ├── salesforce_sample.csv
    ├── aws_iam_sample.csv
    └── azure_entra_sample.csv
```

---

## 🔌 Supported Sources

| Platform | Typical Columns |
|-----------|----------------|
| **Salesforce** | `Username, Email, Profile, UserRole, IsMFAEnabled, LastLoginDate, ManagerId` |
| **AWS IAM** | `user, mfa_active, password_last_changed, access_key_1_last_rotated, group_list, password_last_used` |
| **Azure Entra ID** | `User principal name, Roles, MFA State, Last sign-in date, Manager` |
| **Generic CSV** | `username, email, role, is_admin, mfa_enabled, last_login, creds_last_rotated, has_manager` |

AuditGuard automatically normalizes fields and handles various date/boolean formats.

---

## 🧱 Architecture

| Layer | Description |
|--------|--------------|
| **Normalization** | Converts heterogeneous IAM exports into a unified schema. |
| **Risk Engine** | Classifies users based on MFA, inactivity, credential rotation, ownership, and excessive role criteria. |
| **Framework Mapper** | Maps findings to NIST, ISO 27001, PCI DSS, and SOC 2 control IDs. |
| **UI (Streamlit)** | Tabs for *Overview*, *Findings & Filters*, *Framework Mapping*, and *Evidence & Export*. |

---

## 📊 Example Findings

| Severity | Example | Frameworks |
|-----------|----------|-------------|
| **High** | Admin with MFA disabled | NIST AC-2(1), ISO A.9.2.3, PCI 8.3.1, SOC2 CC6.6 |
| **High** | Credentials not rotated >90 days | NIST IA-5(1), ISO A.9.2.4, PCI 8.3.6, SOC2 CC6.6 |
| **Medium** | User inactive >60 days | NIST AC-2(3), ISO A.9.2.6, SOC2 CC6.2 |
| **Medium** | Elevated rights with business role | NIST AC-6, ISO A.9.1.2, PCI 7.1.1, SOC2 CC6.3 |

---

## 🎯 Demo Flow (2–3 Minutes)

1. **Overview:** “AuditGuard normalizes IAM exports, flags risks, and maps them to frameworks.”  
2. **Load Sample Data:** Show Salesforce, AWS, and Azure normalization.  
3. **Findings & Filters:** Point to KPIs and severity bar chart; switch to compact view.  
4. **Framework Mapping:** Show grouped findings and framework alignment.  
5. **Evidence & Export:** Download the executive summary and CSV.

---

## 🔒 Security & Privacy

- Runs locally; no data leaves your machine unless hosted.  
- Designed for visibility and education — not a production IAM or CSPM substitute.  
- When testing real exports, remove PII before sharing externally.

---

## 🛣️ Roadmap

- Remediation guidance per finding  
- Role-based views (CISO vs Admin)  
- Connectors for Okta, Workday, and Azure Graph  
- YAML/JSON policy linting for least-privilege drift detection

---

## 🙋 About the Author

**Wachiraya “Tanny” Meevasana** — Security Solutions Consultant  
SaaS security, IAM, and compliance automation • San Francisco  
🎓 M.S. Cybersecurity (CSUDH) • Speaker at INTA & LegalTech events

---

## ❤️ Acknowledgments

Built with Python, Streamlit, and too much coffee ☕  
Designed to make compliance **accessible, transparent, and demo-ready**.
