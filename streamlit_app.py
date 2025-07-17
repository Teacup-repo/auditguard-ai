# streamlit_app.py

import streamlit as st
from datetime import datetime, timedelta
import random
import time

# ---------------------------
# Utility Functions
# ---------------------------

def check_access(user, resource):
    allowed_users = {
        "alice": ["secrets", "audit logs"],
        "bob": ["models"],
        "tanny": ["secrets", "models"]
    }
    return resource in allowed_users.get(user.lower(), [])

def calculate_risk_score(user, resource):
    base_risk = {
        "secrets": 80,
        "audit logs": 65,
        "models": 45
    }.get(resource, 50)
    if datetime.now().hour < 6 or datetime.now().hour > 22:
        base_risk += 10  # risky hour
    return min(base_risk + random.randint(-5, 5), 100)

def get_compliance_checks():
    return {
        "Firewall Rules": {
            "result": "✅ All inbound traffic restricted by default.",
            "frameworks": ["NIST SC-7", "CIS Control 9.1", "ISO 27001 A.13.1.1"]
        },
        "Encryption at Rest": {
            "result": "✅ AES-256 enabled across storage buckets.",
            "frameworks": ["PCI DSS 3.5", "NIST SC-12", "ISO 27001 A.10.1"]
        },
        "IAM Policy Check": {
            "result": "⚠️ Admin role assigned to multiple users.",
            "frameworks": ["PCI DSS 7.1", "NIST AC-2", "ISO 27001 A.9.2.3"]
        },
        "Public S3 Buckets": {
            "result": "❌ 2 buckets with public-read access.",
            "frameworks": ["CIS Control 3.4", "NIST SC-28", "ISO 27001 A.8.2"]
        },
        "SSH Access": {
            "result": "✅ Key-based authentication enforced.",
            "frameworks": ["NIST IA-2", "CIS Control 5.2", "ISO 27001 A.9.4"]
        },
        "Security Groups": {
            "result": "⚠️ Some groups allow 0.0.0.0/0 for SSH.",
            "frameworks": ["CIS Control 4.1", "NIST AC-4", "ISO 27001 A.13.1.3"]
        }
    }

def generate_fake_logs():
    users = ["alice", "bob", "tanny", "admin"]
    resources = ["secrets", "audit logs", "models"]
    logs = []
    for _ in range(15):
        user = random.choice(users)
        res = random.choice(resources)
        status = "allowed" if check_access(user, res) else "denied"
        risk = calculate_risk_score(user, res)
        logs.append({
            "timestamp": datetime.now() - timedelta(minutes=random.randint(1, 500)),
            "user": user,
            "resource": res,
            "access": status,
            "risk_score": risk if status == "allowed" else "N/A"
        })
    return sorted(logs, key=lambda x: x["timestamp"], reverse=True)

def fake_incidents():
    return [
        {"time": "08:12", "event": "🚨 Unauthorized access blocked (bob > secrets)"},
        {"time": "08:30", "event": "✅ IAM policy scan completed (2 warnings)"},
        {"time": "08:45", "event": "🔍 Analyst reviewed public S3 exposure"},
        {"time": "09:00", "event": "🛡️ SOC team confirmed low risk — no breach"},
    ]

def simulate_vault_fetch(path="/secret/data/db-creds"):
    time.sleep(1.0)
    return {
        "username": "vault_user",
        "password": "hunter2!",
        "rotation": "2025-06-20",
        "fetched_from": path
    }

# ---------------------------
# Streamlit UI
# ---------------------------

st.set_page_config(page_title="AuditGuard AI", page_icon="🛡️")
st.title("🛡️ AuditGuard AI – Secure Infrastructure Dashboard")

# --- Access Control Section ---
st.header("🔐 User Access Control")
user = st.text_input("Enter your username:")
resource = st.selectbox("Select a resource to access:", ["secrets", "audit logs", "models"])

if st.button("Check Access"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if check_access(user, resource):
        score = calculate_risk_score(user, resource)
        st.success(f"✅ {user} has access to '{resource}'.")
        st.info(f"🧠 Risk Score: {score}/100 at {timestamp}")
        if score >= 80:
            st.warning("🚨 High-risk access — consider alerting SOC.")
    else:
        st.error(f"❌ Access denied for {user}.")
        st.info(f"🧠 Risk Score: N/A")

# --- Compliance Dashboard ---
st.markdown("---")
st.header("📋 Infrastructure Compliance Dashboard")
compliance_data = get_compliance_checks()
for check, details in compliance_data.items():
    result = details["result"]
    frameworks = ", ".join(details["frameworks"])
    msg = f"{check}: {result}\n\n🔎 **Compliance Mapping:** {frameworks}"

    if result.startswith("✅"):
        st.success(msg)
    elif result.startswith("⚠️"):
        st.warning(msg)
    else:
        st.error(msg)

# --- AI-Powered Compliance Auditor ---
st.markdown("---")
st.header("🧠 AI-Powered Compliance Auditor")

if st.button("Run AI Audit Review"):
    with st.spinner("Summoning local AI auditor..."):
        try:
            from gpt4all import GPT4All

            @st.cache_resource
            def load_model():
                return GPT4All("mistral-7b-openorca.Q4_0.gguf")

            model = load_model()

            report = "\n".join([f"{k}: {v['result']}" for k, v in compliance_data.items()])
            prompt = f"""
You are a security auditor. Review this compliance report and identify risks, misconfigurations, and violations. Tie them to NIST, PCI DSS, or ISO 27001 where possible:

{report}
"""
            output = model.generate(prompt, max_tokens=500)
            st.success("✅ AI Audit Summary:")
            st.write(output)

        except Exception as e:
            st.error(f"❌ Error running GPT4All: {str(e)}")

# --- Access Logs ---
st.markdown("---")
st.header("🕵️ Access Attempt Logs")
logs = generate_fake_logs()
for entry in logs:
    msg = f"{entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | {entry['user']} tried to access '{entry['resource']}' — {entry['access']}"
    if entry["access"] == "allowed":
        msg += f" | Risk Score: {entry['risk_score']}"
        st.info(msg)
    else:
        st.error(msg)

# --- Incident Timeline ---
st.markdown("---")
st.header("🧯 Recent Incident Timeline")
timeline = fake_incidents()
for item in timeline:
    st.markdown(f"- **{item['time']}**: {item['event']}")

# --- Vault API Simulation ---
st.markdown("---")
st.header("🔐 Vault Secret API Simulation")
if st.button("Simulate Vault Secret Fetch"):
    secrets = simulate_vault_fetch()
    st.json(secrets)
    st.success("✔️ Simulated Vault secret fetch complete.")

# --- Compliance Framework Legend ---
with st.expander("🗂️ Compliance Framework Legend"):
    st.markdown("""
- **NIST**: NIST SP 800-53 Rev 5
- **PCI DSS**: Payment Card Industry Data Security Standard v4.0
- **ISO 27001**: International Standard for Information Security
- **CIS**: Center for Internet Security Controls v8
""")

# --- Footer ---
st.markdown("---")
st.caption("Built with ❤️ by Tanny — Secure Infra AI Capstone | July 2025")
