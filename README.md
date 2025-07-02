# 🛡️ AuditGuard AI – Secure Infrastructure Design  
[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://auditguard-ai.streamlit.app/)

Welcome to **AuditGuard AI**, a security dashboard that simulates real-world infrastructure hardening using IAM, encryption, policy enforcement, and AI-assisted compliance insights.

This capstone project was built to demonstrate how modern organizations can visualize, assess, and respond to security risks in real-time — aligning with frameworks like **PCI-DSS**, **NIST**, and **GDPR**.

---

## 🔧 Features

- 🔐 **Role-Based Access Simulation**: Enforce RBAC using mock IAM rules and simulate user attempts to access sensitive resources like secrets and models.
- 🤖 **AI-Powered Risk Scoring**: Assign dynamic risk scores to access attempts based on time-of-day and user role.
- 📋 **Compliance Check Dashboard**: Visual flags for misconfigurations such as public S3 buckets, overly permissive security groups, and IAM overprovisioning.
- 🕵️ **Live Access Logs**: Generate mock access logs with risk insights for SOC-style investigation.
- 🧯 **Incident Timeline**: Simulate incident response actions and events over time.
- 🔐 **Vault Integration Ready**: Framework prepared to integrate HashiCorp Vault secrets and key-based policies.


---

## 📂 Tools & Libraries Used

| Tool/Library         | Purpose                                      |
|----------------------|----------------------------------------------|
| `Streamlit`          | Frontend UI for live dashboard               |
| `Python`             | Core logic and data simulation               |
| `AWS IAM` (simulated)| Role-based access and least privilege        |
| `HashiCorp Vault`    | Secrets and encryption key management (planned) |
| `OpenSSL`            | Demonstrated data-at-rest encryption         |
| `NIST/PCI DSS`       | Compliance benchmarks for checks             |


## 🎯 Real-World Use Cases

✅ Accelerate **audit readiness** with proactive misconfig tracking

🧠 Help **SOC teams** focus on risky access attempts with AI scoring

🔒 Strengthen **data protection policies** using least privilege & encryption

📊 Support **compliance reporting** for PCI DSS and NIST 800-53

🔁 Easily extensible to **AWS Config, Azure Defender**, and real Vault APIs

---
## 💡 Why AuditGuard AI Matters

🔍 Shift-Left Security: Catch misconfigs and risky access early — no need to wait for quarterly audits or breach reports.

🧠 AI-Powered Prioritization: Helps SOC teams focus on what matters with contextual risk scoring and compliance flags.

🔐 Zero Trust-Ready Architecture: Implements least privilege and role-based controls, simulating how real infra isolates critical assets.

🚀 SaaS-Savvy Compliance: Supports PCI-DSS, NIST 800-53, and GDPR principles — making it perfect for fintech, legal, and SaaS environments.

---

## 📸 Demo Screenshots

### 🔐 Access Control & AI-Powered Risk Scoring
![Access Control Demo](https://github.com/Teacup-repo/auditguard-ai/raw/main/LandingPageDemo.png)

### 🔑 Simulated Vault Secret Fetch (API Ready)
![Vault API Simulation](https://github.com/Teacup-repo/auditguard-ai/raw/main/IRand%20APIVault.png)


## 🚀 Getting Started

1. Clone the repo:
   ```bash
   git clone https://github.com/Teacup-repo/auditguard-ai.git
   cd auditguard-ai
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
3. Run the app:
   ```bash
   streamlit run streamlit_app.py
---

## 👤 Sample Users for Testing

Use these usernames to test access control and risk scoring:

| Username | Allowed Resources         | Notes                            |
|----------|---------------------------|----------------------------------|
| `alice`  | `secrets`, `audit logs`   | High-risk data access            |
| `bob`    | `models`                  | Restricted to non-sensitive data |
| `tanny`  | `secrets`, `models`       | Mixed access                     |
| `admin`  | `None` (denied by default)| Used for testing blocked access  |

Try typing one of these into the dashboard to simulate access attempts and AI-driven risk scoring!

---

## 🆚 AuditGuard AI vs Traditional Tools

| **Feature / Tool**        | **AuditGuard AI**                                       | **SIEM (e.g. Splunk, Sentinel)**                     | **SolarWinds**                                   |
|---------------------------|----------------------------------------------------------|------------------------------------------------------|--------------------------------------------------|
| 🔍 **Purpose**             | Infra compliance demo + risk scoring                    | Log ingestion, correlation, alerting                 | Network monitoring and performance management    |
| 🌐 **Cloud Integration**   | ✅ AWS, Azure, GCP, Vault (extensible)                   | ✅ Native integrations                                | ⚠️ Primarily on-prem & hybrid                    |
| 🧠 **AI/ML Risk Insights** | ✅ Risk score based on user/time context                 | ✅ Available in advanced tier                         | ❌ Not AI-driven                                 |
| 🛠️ **Customization**       | ✅ Fully open and modifiable Python/Streamlit code       | ⚠️ Limited by license/tier                            | ⚠️ Requires plugins or separate tools            |
| 💰 **Cost to Use**         | ✅ Free & open-source for learning/demo                 | ❌ Expensive (Splunk charges per GB/day)             | ❌ Licensing required                            |
| 🎓 **Educational Value**   | ✅ Great for IAM, Vault, RBAC, encryption learning       | ⚠️ Complex setup, steep learning curve               | ⚠️ Focuses more on IT ops than security posture  |
| 🛡️ **Compliance Frameworks** | ✅ PCI DSS, NIST, GDPR simulated checks                 | ✅ If logs and infra are configured properly          | ⚠️ Limited security compliance visibility        |

---

✨ Author
Wachiraya Meevasana (Tanny)
🔐 Cybersecurity Analyst | SaaS Security | Compliance Automation📍 San Francisco | 🎓 CSUDH Cybersecurity Master's

---
❤️ Shoutout
Built with love, Python, and too much coffee ☕
