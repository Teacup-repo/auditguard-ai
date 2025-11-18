# AuditGuard – IAM Audit Readiness Dashboard (Enterprise Edition)
# Author: Tanny Meevasana
# Notes: Polished, enterprise-grade Streamlit app optimized for demo storytelling (Figma, presales)

import re
from datetime import datetime
from typing import List, Tuple, Dict

import pandas as pd
import streamlit as st

# --------------------------- Page / Theming ---------------------------
st.set_page_config(
    page_title="AuditGuard – IAM Audit Readiness (Enterprise)",
    page_icon="🛡️",
    layout="wide",
    menu_items={
        "Get Help": "mailto:tanny.meeva@gmail.com",
        "Report a bug": "mailto:tanny.meeva@gmail.com",
        "About": "AuditGuard – IAM identity & access readiness demo (Streamlit)"
    }
)

# ---- Minimal CSS polish for enterprise look
st.markdown(
    """
    <style>
      /* Tighten fonts and add subtle card styles */
      .main {padding-top: 1rem;}
      .stMetric {background: rgba(0,0,0,0.03); border-radius: 12px; padding: 12px;}
      .ag-card {border: 1px solid rgba(0,0,0,0.08); border-radius: 14px; padding: 18px; margin-bottom: 12px; background: rgba(255,255,255,0.6);}
      .ag-inline {display:flex; gap:12px; flex-wrap: wrap;}
      .ag-pill {display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; border:1px solid rgba(0,0,0,0.12);}
      .ag-sev-High {background:#fff0f0;}
      .ag-sev-Medium {background:#fff7e6;}
      .ag-sev-Low {background:#f0fff4;}
      .ag-muted {color:#666;}
      .ag-hint {font-size:13px; color:#666;}
      .block-container {padding-top: 1rem; padding-bottom: 2rem;}
      .stTabs [data-baseweb="tab-list"] {gap: 8px;}
      .stTabs [data-baseweb="tab"] {border-radius: 12px; padding: 8px 12px;}
      footer {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🛡️ AuditGuard – IAM Audit Readiness (Enterprise)")
st.caption("Prototype for real-time IAM control visibility and framework mapping (NIST 800-53, ISO 27001, PCI DSS, SOC 2)")

# --------------------------- Constants ---------------------------
CONTROL_MAP: Dict[str, Dict[str, object]] = {
    "MFA_DISABLED_ADMIN": {
        "description": "Admin account with MFA disabled",
        "nist": ["AC-2(1)", "IA-2(1)"],
        "iso": ["A.9.2.3", "A.9.4.2"],
        "pci": ["8.3.1", "8.4.2"],
        "soc2": ["CC6.1", "CC6.6"],
        "severity": "High",
    },
    "NO_MFA_USER": {
        "description": "User without MFA enabled",
        "nist": ["IA-2(1)"],
        "iso": ["A.9.4.2"],
        "pci": ["8.3.1"],
        "soc2": ["CC6.6"],
        "severity": "Medium",
    },
    "INACTIVE_60": {
        "description": "User inactive > 60 days",
        "nist": ["AC-2(3)"],
        "iso": ["A.9.2.6"],
        "pci": ["8.2.6"],
        "soc2": ["CC6.2"],
        "severity": "Medium",
    },
    "STALE_CREDS_90": {
        "description": "Credentials not rotated > 90 days",
        "nist": ["IA-5(1)"],
        "iso": ["A.9.2.4"],
        "pci": ["8.3.6"],
        "soc2": ["CC6.6"],
        "severity": "High",
    },
    "ORPHANED_ACCOUNT": {
        "description": "Account without active owner/manager",
        "nist": ["AC-2"],
        "iso": ["A.9.2.1"],
        "pci": ["7.1.2"],
        "soc2": ["CC6.1"],
        "severity": "High",
    },
    "EXCESSIVE_ROLE": {
        "description": "Elevated role not justified (non-admin in admin group)",
        "nist": ["AC-6"],
        "iso": ["A.9.1.2"],
        "pci": ["7.1.1"],
        "soc2": ["CC6.3"],
        "severity": "Medium",
    },
}

FW_LABEL_TO_COL = {"NIST 800-53": "nist", "ISO 27001": "iso", "PCI DSS": "pci", "SOC 2": "soc2"}
BASE_DETAIL_COLS = [
    "source",
    "finding_code",
    "finding",
    "severity",
    "username",
    "last_login",
    "creds_last_rotated",
    "has_manager",
]

# --------------------------- Utilities ---------------------------
def _parse_bool(v):
    if pd.isna(v):
        return None
    s = str(v).strip().lower()
    if s in ("true","t","yes","y","1","enabled","active","on"): return True
    if s in ("false","f","no","n","0","disabled","inactive","off"): return False
    return None

def _parse_date(v):
    if pd.isna(v) or str(v).strip() == "":
        return None
    for fmt in ("%Y-%m-%d","%Y/%m/%d","%m/%d/%Y","%d/%m/%Y","%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(str(v), fmt)
        except Exception:
            continue
    return None

# --------------------------- Normalizers ---------------------------
def normalize_salesforce(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "username": df.get("Username", df.get("UserName")),
        "email": df.get("Email"),
        "role": df.get("Profile", df.get("UserRole")),
        "is_admin": df.get("Profile", "").astype(str).str.contains("System Administrator", case=False, na=False),
        "mfa_enabled": df.get("IsMFAEnabled", df.get("MfaEnabled", False)).apply(_parse_bool),
        "last_login": df.get("LastLoginDate").apply(_parse_date),
        "creds_last_rotated": None,
        "has_manager": df.get("ManagerId").notna() if "ManagerId" in df.columns else True,
    })

def normalize_aws_iam(df: pd.DataFrame) -> pd.DataFrame:
    last_rot = df.get("access_key_1_last_rotated", df.get("password_last_changed"))
    role_guess = df.get("group_list", "").astype(str)
    return pd.DataFrame({
        "username": df.get("user"),
        "email": None,
        "role": role_guess,
        "is_admin": role_guess.str.contains("Administrator", case=False, na=False),
        "mfa_enabled": df.get("mfa_active").apply(_parse_bool),
        "last_login": df.get("password_last_used", df.get("user_creation_time")).apply(_parse_date),
        "creds_last_rotated": last_rot.apply(_parse_date) if isinstance(last_rot, pd.Series) else None,
        "has_manager": True,
    })

def normalize_azure_entra(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "username": df.get("User principal name", df.get("UserPrincipalName")),
        "email": df.get("User principal name", df.get("UserPrincipalName")),
        "role": df.get("Roles", df.get("Directory roles")),
        "is_admin": df.get("Roles", "").astype(str).str.contains("Global Administrator|Privileged", case=False, na=False),
        "mfa_enabled": df.get("MFA State", df.get("MFA")).apply(_parse_bool),
        "last_login": df.get("Last sign-in date", df.get("LastSignInDate")).apply(_parse_date),
        "creds_last_rotated": None,
        "has_manager": df.get("Manager").notna() if "Manager" in df.columns else True,
    })

def normalize_generic(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "username": df.get("username", df.get("user")),
        "email": df.get("email"),
        "role": df.get("role", df.get("group")),
        "is_admin": df.get("is_admin", df.get("admin")).apply(_parse_bool) if "is_admin" in df.columns or "admin" in df.columns else False,
        "mfa_enabled": df.get("mfa_enabled", df.get("MFA")).apply(_parse_bool) if "mfa_enabled" in df.columns or "MFA" in df.columns else None,
        "last_login": df.get("last_login").apply(_parse_date) if "last_login" in df.columns else None,
        "creds_last_rotated": df.get("creds_last_rotated").apply(_parse_date) if "creds_last_rotated" in df.columns else None,
        "has_manager": df.get("has_manager").apply(_parse_bool) if "has_manager" in df.columns else True,
    })

NORMALIZERS = {
    "Salesforce": normalize_salesforce,
    "AWS IAM": normalize_aws_iam,
    "Azure Entra ID": normalize_azure_entra,
    "Generic CSV": normalize_generic,
}

# --------------------------- Risk logic ---------------------------
def classify_row(row) -> List[Tuple[str, str]]:
    findings: List[Tuple[str, str]] = []
    is_admin = bool(row.get("is_admin") or (row.get("role") and "admin" in str(row.get("role")).lower()))
    mfa = row.get("mfa_enabled")
    last_login = row.get("last_login")
    creds_rot = row.get("creds_last_rotated")
    has_manager = row.get("has_manager", True)

    if is_admin and (mfa is False or mfa is None):
        findings.append(("MFA_DISABLED_ADMIN", "Admin without MFA"))
    elif mfa is False:
        findings.append(("NO_MFA_USER", "User without MFA"))

    if isinstance(last_login, datetime):
        days = (datetime.now() - last_login).days
        if days > 60:
            findings.append(("INACTIVE_60", f"Inactive for {days} days"))
    else:
        findings.append(("INACTIVE_60", "No last_login timestamp available"))

    if isinstance(creds_rot, datetime):
        days = (datetime.now() - creds_rot).days
        if days > 90:
            findings.append(("STALE_CREDS_90", f"Credentials last rotated {days} days ago"))

    if has_manager is False:
        findings.append(("ORPHANED_ACCOUNT", "No active manager assigned"))

    role = str(row.get("role") or "")
    if ("finance" in role.lower() or "hr" in role.lower()) and is_admin:
        findings.append(("EXCESSIVE_ROLE", f"Elevated rights with business role: {role}"))

    return findings

def expand_findings(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, r in df.iterrows():
        issues = classify_row(r)
        if not issues:
            rows.append({
                **r.to_dict(),
                "finding_code": None,
                "finding": "No finding",
                "severity": "Low",
                "nist": "",
                "iso": "",
                "pci": "",
                "soc2": "",
            })
        else:
            for code, reason in issues:
                meta = CONTROL_MAP[code]
                rows.append({
                    **r.to_dict(),
                    "finding_code": code,
                    "finding": f"{meta['description']} — {reason}",
                    "severity": meta["severity"],
                    "nist": ", ".join(meta["nist"]),
                    "iso": ", ".join(meta["iso"]),
                    "pci": ", ".join(meta["pci"]),
                    "soc2": ", ".join(meta["soc2"]),
                })
    return pd.DataFrame(rows)


# --------------------------- Sidebar Nav ---------------------------
st.sidebar.header("Navigation")
page = st.sidebar.radio(
    "Go to",
    ["Overview", "Upload & Normalize", "Findings & Filters", "Framework Mapping", "Evidence & Export"],
    index=0
)
st.sidebar.markdown("---")
st.sidebar.subheader("Severity")
sev_filter = st.sidebar.multiselect("Show severities", options=["High", "Medium", "Low"], default=["High","Medium","Low"])
st.sidebar.subheader("Frameworks")
fw_selected = st.sidebar.multiselect("Map to", options=list(FW_LABEL_TO_COL.keys()), default=list(FW_LABEL_TO_COL.keys()))

# --------------------------- Sample Data Help ---------------------------
with st.expander("📎 Sample CSV formats (click to expand)"):
    st.markdown("""
**Salesforce:** `Username, Email, Profile, UserRole, IsMFAEnabled, LastLoginDate, ManagerId`  
**AWS IAM (Credential Report):** `user, mfa_active, password_last_changed, access_key_1_last_rotated, group_list, password_last_used`  
**Azure Entra ID:** `User principal name, Roles, MFA State, Last sign-in date, Manager`  
**Generic CSV:** `username, email, role, is_admin, mfa_enabled, last_login, creds_last_rotated, has_manager`
    """)

# --------------------------- Data Stage ---------------------------
@st.cache_data(show_spinner=False)
def _load_and_normalize(uploads: list) -> pd.DataFrame:
    frames = []
    for src, up in uploads:
        df = pd.read_csv(up)
        norm = NORMALIZERS[src](df)
        norm["source"] = src
        frames.append(norm)
    if not frames:
        return pd.DataFrame()
    data = pd.concat(frames, ignore_index=True).fillna({"mfa_enabled": False, "has_manager": True})
    return data

uploads: list = []
cols = st.columns(3) if page != "Overview" else st.columns(1)
rng = 3 if page != "Overview" else 1
for i in range(rng):
    with cols[i % len(cols)]:
        src = st.selectbox(f"Source #{i+1}", ["—", "Salesforce", "AWS IAM", "Azure Entra ID", "Generic CSV"], key=f"src{i}")
        file = st.file_uploader(f"Upload CSV #{i+1}", type=["csv"], key=f"file{i}")
        if src != "—" and file is not None:
            uploads.append((src, file))

data = _load_and_normalize(uploads) if uploads else pd.DataFrame()
findings = expand_findings(data) if not data.empty else pd.DataFrame()

# --------------------------- Pages ---------------------------
def page_overview():
    st.subheader("Why AuditGuard?")
    st.markdown(
        """
        - **One place to see IAM risk posture** across Salesforce, AWS IAM, Azure Entra, or any CSV source.
        - **Story-first demo flow**: summary metrics → filters → framework mapping → exportable evidence.
        - **Enterprise-ready**: identity & access checks, framework mapping (NIST/ISO/PCI/SOC2), CSV export.
        """
    )
    st.markdown("#### What you can demo")
    cols = st.columns(3)
    with cols[0]:
        st.markdown('<div class="ag-card"><b>Normalize</b><br/><span class="ag-muted">Ingest heterogeneous IAM exports and unify fields.</span></div>', unsafe_allow_html=True)
    with cols[1]:
        st.markdown('<div class="ag-card"><b>Classify risk</b><br/><span class="ag-muted">MFA gaps, inactivity, rotation, owners & roles.</span></div>', unsafe_allow_html=True)
    with cols[2]:
        st.markdown('<div class="ag-card"><b>Map to frameworks</b><br/><span class="ag-muted">NIST, ISO 27001, PCI DSS, SOC 2 controls.</span></div>', unsafe_allow_html=True)
    st.info("Use the sidebar to navigate. Upload sample CSVs to see the end-to-end story.")

def page_upload():
    st.subheader("📥 Upload & Normalize")
    if data.empty:
        st.warning("Upload at least one CSV to continue.")
        return
    st.success(f"Loaded **{len(data)}** rows from **{data['source'].nunique()}** source(s).")
    st.dataframe(data, use_container_width=True, hide_index=True)

def page_findings():
    st.subheader("📊 Posture Summary")
    if findings.empty:
        st.info("No findings yet. Upload IAM exports above.")
        return

    # KPI metrics
    total_accts = findings["username"].nunique()
    high = findings.query("severity == 'High'")["username"].nunique()
    medium = findings.query("severity == 'Medium'")["username"].nunique()
    low = findings.query("severity == 'Low'")["username"].nunique()

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Accounts analyzed", total_accts)
    m2.metric("High (unique users)", high)
    m3.metric("Medium (unique users)", medium)
    m4.metric("Low (unique users)", low)

    # Severity filter
    df_show = findings[findings["severity"].isin(sev_filter)].copy() if sev_filter else findings.copy()

    # Simple matplotlib bar chart (one plot, no explicit colors)
    import matplotlib.pyplot as plt
    counts = df_show["severity"].value_counts().reindex(["High","Medium","Low"]).fillna(0)
    fig, ax = plt.subplots()
    ax.bar(counts.index.astype(str), counts.values)
    ax.set_title("Findings by Severity")
    ax.set_xlabel("Severity")
    ax.set_ylabel("Count")
    st.pyplot(fig)

    st.markdown("#### Findings (filtered)")
    pretty = df_show.rename(columns={
        "username":"Username","email":"Email","role":"Role","is_admin":"Is Admin",
        "mfa_enabled":"MFA Enabled","last_login":"Last Login","creds_last_rotated":"Creds Rotated",
        "has_manager":"Has Manager","severity":"Severity","finding":"Finding",
        "nist":"NIST 800-53","iso":"ISO 27001","pci":"PCI DSS","soc2":"SOC 2","source":"Source"
    })
    st.dataframe(pretty, use_container_width=True, hide_index=True, height=420)

def page_framework_mapping():
    st.subheader("🧭 Framework Mapping & Grouped Summary")
    if findings.empty:
        st.info("Upload data to see mappings.")
        return

    # 1) Framework filter
    chosen_fw_raw = [FW_LABEL_TO_COL[k] for k in fw_selected] if fw_selected else []

    # 2) Filter to rows that have ANY mapping in selected frameworks
    if chosen_fw_raw:
        mask = findings[chosen_fw_raw].apply(lambda r: any(bool(str(x).strip()) for x in r), axis=1)
        filtered_df = findings.loc[mask].copy()
    else:
        filtered_df = findings.copy()

    # 3) Normalize "Finding Type" (remove numeric parts)
    def _normalize_msg(s: str) -> str:
        return re.sub(r"\\d+", "N", str(s))

    filtered_df["Finding Type"] = filtered_df["finding"].apply(_normalize_msg)

    # 4) Group
    group_cols = ["finding_code", "Finding Type", "severity"]
    def _join_uniq(series: pd.Series) -> str:
        vals = [str(x).strip() for x in series if str(x).strip()]
        return ", ".join(sorted(set(vals)))

    present_fw_cols = [c for c in FW_LABEL_TO_COL.values() if c in filtered_df.columns]
    agg_dict = {"source": _join_uniq, **{c: _join_uniq for c in present_fw_cols}, "username": "nunique"}

    grouped = (
        filtered_df.groupby(group_cols, dropna=False).agg(agg_dict).reset_index()
        .rename(columns={
            "finding_code":"Finding Code",
            "severity":"Severity",
            "source":"Sources",
            "username":"Impacted Users",
            **{v:k for k,v in FW_LABEL_TO_COL.items() if v in present_fw_cols}
        })
    )

    # Sort and present
    sort_cols = ["Severity", "Impacted Users"] if "Impacted Users" in grouped.columns else ["Severity"]
    grouped = grouped.sort_values(sort_cols, ascending=[True, False])
    st.dataframe(grouped, use_container_width=True, hide_index=True)

    st.caption("One row per finding type with impacted users, sources, and mapped controls.")

def page_evidence_export():
    st.subheader("📄 Evidence & Export")
    if findings.empty:
        st.info("Upload data to generate evidence.")
        return
    csv = findings.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Export Findings CSV", csv, file_name="auditguard_findings.csv", mime="text/csv")

    with st.expander("🗂️ Framework Legend"):
        st.markdown("""
- **NIST 800-53 Rev.5** (e.g., AC-2, AC-6, IA-2, IA-5)  
- **ISO/IEC 27001:2022** (Annex A, e.g., A.9.x)  
- **PCI DSS v4.0** (Req. 7–8 user access & auth)  
- **SOC 2** (Common Criteria CC6.x)
        """)

    st.markdown('<div class="ag-card ag-muted">Built by Tanny • AuditGuard prototype (IAM identity & access readiness)</div>', unsafe_allow_html=True)

# --------------------------- Router ---------------------------
if page == "Overview":
    page_overview()
elif page == "Upload & Normalize":
    page_upload()
elif page == "Findings & Filters":
    page_findings()
elif page == "Framework Mapping":
    page_framework_mapping()
elif page == "Evidence & Export":
    page_evidence_export()
