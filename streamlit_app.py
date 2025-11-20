# AuditGuard – IAM Audit Readiness (Enterprise Edition v2, with Week 15 & 16)
# Author: Tanny Meevasana
# Purpose: Enterprise-polished Streamlit app for presales and investor demos

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
        "About": "AuditGuard – IAM identity & access readiness (enterprise demo)"
    }
)

# Minimal CSS for clean, neutral enterprise look
st.markdown(
    """
    <style>
      .main {padding-top: 0.5rem;}
      .ag-brand {display:flex; align-items:center; justify-content:space-between; padding:10px 12px; border-bottom:1px solid rgba(0,0,0,0.06); margin-bottom:10px;}
      .ag-brand .left {display:flex; gap:10px; align-items:center;}
      .ag-badge {padding:2px 8px; border-radius:999px; border:1px solid rgba(0,0,0,0.1); font-size:12px;}
      .stMetric {background: rgba(0,0,0,0.03); border-radius: 12px; padding: 12px;}
      .ag-card {border: 1px solid rgba(0,0,0,0.08); border-radius: 14px; padding: 18px; margin-bottom: 12px; background: rgba(255,255,255,0.6);}
      .ag-muted {color:#666;}
      .ag-note {font-size:12px; color:#666;}
      .ag-hstack {display:flex; gap:10px; align-items:center;}
      .ag-pill {display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; border:1px solid rgba(0,0,0,0.12);}
      .ag-sev-High {background:#fff0f0;}
      .ag-sev-Medium {background:#fff7e6;}
      .ag-sev-Low {background:#f0fff4;}
      footer {visibility: hidden;}
      /* Table density */
      .compact-table table {font-size: 12px;}
    </style>
    """,
    unsafe_allow_html=True
)

def brand_bar():
    st.markdown(
        """
        <div class="ag-brand">
          <div class="left">
            <span style="font-size:20px">🛡️ <b>AuditGuard</b></span>
            <span class="ag-badge">Enterprise Demo</span>
          </div>
          <div class="ag-note">IAM readiness • Framework mapping • Evidence export</div>
        </div>
        """,
        unsafe_allow_html=True
    )

brand_bar()

st.subheader("IAM Audit Readiness")
st.caption("Normalize IAM exports, classify identity risk, map to frameworks, and export evidence — built for presales, security leaders, and investors.")

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

# --------------------------- Framework Coverage (Week 15) ---------------------------
FW_PAIRS = [("NIST 800-53", "nist"), ("ISO 27001", "iso"), ("PCI DSS", "pci"), ("SOC 2", "soc2")]

def build_framework_universe() -> Dict[str, set]:
    """Universe of controls your rules touch for each framework."""
    universe = {fw: set() for fw, _ in FW_PAIRS}
    for code, meta in CONTROL_MAP.items():
        for fw, key in FW_PAIRS:
            for ctrl in meta.get(key, []):
                if str(ctrl).strip():
                    universe[fw].add(ctrl.strip())
    return universe

def compute_framework_scores(findings_df: pd.DataFrame) -> pd.DataFrame:
    """
    Any presence of a finding_code mapped to a control marks that control as FAIL.
    Controls with no related findings are PASS.
    """
    universe = build_framework_universe()
    failing = {fw: set() for fw, _ in FW_PAIRS}

    if not findings_df.empty:
        for _, r in findings_df.iterrows():
            code = r.get("finding_code")
            if not code or code not in CONTROL_MAP:
                continue
            meta = CONTROL_MAP[code]
            for fw, key in FW_PAIRS:
                for ctrl in meta.get(key, []):
                    if str(ctrl).strip():
                        failing[fw].add(ctrl.strip())

    rows = []
    for fw, controls in universe.items():
        implemented = len(controls)
        failed = len(failing[fw] & controls)
        passed = max(0, implemented - failed)
        compliance = (passed / implemented * 100.0) if implemented else 0.0
        rows.append({
            "Framework": fw,
            "Controls Implemented": implemented,
            "Controls Passing": passed,
            "Controls Failing": failed,
            "Compliance %": round(compliance, 1),
        })
    return pd.DataFrame(rows)

# --------------------------- Sidebar: Settings ---------------------------
st.sidebar.header("Settings")
density = st.sidebar.select_slider("Table density", options=["Comfortable","Compact"], value="Comfortable")
sev_filter = st.sidebar.multiselect("Show severities", options=["High","Medium","Low"], default=["High","Medium","Low"])
fw_selected = st.sidebar.multiselect("Framework filter", options=list(FW_LABEL_TO_COL.keys()), default=list(FW_LABEL_TO_COL.keys()))
source_filter = st.sidebar.multiselect("Source filter", options=["Salesforce","AWS IAM","Azure Entra ID","Generic CSV"], default=[])

st.sidebar.markdown("---")
use_samples = st.sidebar.button("🔁 Load sample data (demo)")

# --------------------------- Data Stage ---------------------------
@st.cache_data(show_spinner=False)
def load_samples() -> list:
    from io import StringIO
    salesforce = StringIO("""Username,Email,Profile,UserRole,IsMFAEnabled,LastLoginDate,ManagerId
alice,alice@example.com,System Administrator,Admin,true,2025-10-01,123
bob,bob@example.com,Standard User,User,false,2025-09-01,124
carol,carol@example.com,Standard User,User,,2025-06-12,
""")
    aws = StringIO("""user,mfa_active,password_last_changed,access_key_1_last_rotated,group_list,password_last_used,user_creation_time
root,false,2025-01-10,2025-04-01,Administrator,2025-05-01,2024-12-01
dev1,false,2025-02-01,2025-02-10,Developers,2025-10-01,2024-07-01
fin-admin,true,2025-06-01,2025-06-15,Finance-Admin,2025-08-20,2024-08-01
""")
    azure = StringIO("""User principal name,Roles,MFA State,Last sign-in date,Manager
sue@example.com,Global Administrator,enabled,2025-11-01,manager@example.com
lee@example.com,User,disabled,2025-08-01,
kim@example.com,Privileged Role Administrator,enabled,2025-02-10,lead@example.com
""")
    return [("Salesforce", salesforce), ("AWS IAM", aws), ("Azure Entra ID", azure)]

@st.cache_data(show_spinner=False)
def _load_and_normalize(uploads: list) -> pd.DataFrame:
    frames = []
    for src, up in uploads:
        try:
            df = pd.read_csv(up)
        except Exception:
            st.warning(f"Could not read file for source {src}. Ensure CSV format is valid.")
            continue
        normalizer = NORMALIZERS.get(src)
        if not normalizer:
            st.warning(f"No normalizer for source: {src}")
            continue
        norm = normalizer(df)
        norm["source"] = src
        frames.append(norm)
    if not frames:
        return pd.DataFrame()
    data = pd.concat(frames, ignore_index=True).fillna({"mfa_enabled": False, "has_manager": True})
    return data

# Uploaders
uploads: list = []
cols = st.columns(3)
for i in range(3):
    with cols[i]:
        src = st.selectbox(f"Source #{i+1}", ["—", "Salesforce", "AWS IAM", "Azure Entra ID", "Generic CSV"], key=f"src{i}")
        file = st.file_uploader(f"Upload CSV #{i+1}", type=["csv"], key=f"file{i}")
        if src != "—" and file is not None:
            uploads.append((src, file))

if use_samples and not uploads:
    uploads = load_samples()

data = _load_and_normalize(uploads) if uploads else pd.DataFrame()
if not data.empty and source_filter:
    data = data[data["source"].isin(source_filter)].copy()

findings = expand_findings(data) if not data.empty else pd.DataFrame()

# --------------------------- Helper: native chart ---------------------------
def render_severity_chart(df):
    order = ["High", "Medium", "Low"]
    counts = df["severity"].value_counts().reindex(order).fillna(0).astype(int)
    st.bar_chart(counts, height=220)


# --------------------------- Overview Cards ---------------------------
with st.container():
    c1, c2, c3, c4 = st.columns(4)
    if findings.empty:
        c1.metric("Accounts analyzed", 0)
        c2.metric("High (unique users)", 0)
        c3.metric("Medium (unique users)", 0)
        c4.metric("Low (unique users)", 0)
    else:
        total_accts = findings["username"].nunique()
        high = findings.query("severity == 'High'")["username"].nunique()
        medium = findings.query("severity == 'Medium'")["username"].nunique()
        low = findings.query("severity == 'Low'")["username"].nunique()
        c1.metric("Accounts analyzed", total_accts)
        c2.metric("High (unique users)", int(high))
        c3.metric("Medium (unique users)", int(medium))
        c4.metric("Low (unique users)", int(low))

# --------------------------- Tabs ---------------------------
tab_overview, tab_findings, tab_framework, tab_export = st.tabs(
    ["Overview", "Findings & Filters", "Framework Mapping", "Evidence & Export"]
)

with tab_overview:
   
    st.markdown('<div class="ag-card ag-muted">Use the sidebar to switch density, frameworks, severities, and sources. Click “Load sample data” to populate a full story instantly.</div>', unsafe_allow_html=True)
    if data.empty:
        st.info("Upload CSVs (or click “Load sample data”) to begin.")
    else:
        st.success(f"Loaded **{len(data)}** rows from **{data['source'].nunique()}** source(s).")
        st.dataframe(data, use_container_width=True, hide_index=True)

with tab_findings:
    if findings.empty:
        st.info("No findings yet. Upload data or use sample data.")
    else:
        # Apply severity filter
        df_show = findings[findings["severity"].isin(sev_filter)].copy() if sev_filter else findings.copy()

        # Native chart (no matplotlib)
        render_severity_chart(df_show)

        # Table
        pretty = df_show.rename(columns={
            "username":"Username","email":"Email","role":"Role","is_admin":"Is Admin",
            "mfa_enabled":"MFA Enabled","last_login":"Last Login","creds_last_rotated":"Creds Rotated",
            "has_manager":"Has Manager","severity":"Severity","finding":"Finding",
            "nist":"NIST 800-53","iso":"ISO 27001","pci":"PCI DSS","soc2":"SOC 2","source":"Source"
        })
        if density == "Compact":
            st.markdown('<div class="compact-table">', unsafe_allow_html=True)
        st.dataframe(pretty, use_container_width=True, hide_index=True, height=420)
        if density == "Compact":
            st.markdown('</div>', unsafe_allow_html=True)

with tab_framework:
    if findings.empty:
        st.info("Upload data to see mappings.")
    else:
        # --- Coverage scoring (Week 15) ---
        scores_df = compute_framework_scores(findings)
        c1, c2, c3, c4 = st.columns(4)
        if not scores_df.empty:
            overall_controls = int(scores_df["Controls Implemented"].sum())
            overall_fail = int(scores_df["Controls Failing"].sum())
            overall_pass = int(scores_df["Controls Passing"].sum())
            overall_pct = round((overall_pass / overall_controls * 100.0), 1) if overall_controls else 0.0

            c1.metric("Controls Implemented", overall_controls)
            c2.metric("Controls Passing", overall_pass)
            c3.metric("Controls Failing", overall_fail)
            c4.metric("Overall Compliance %", overall_pct)

            st.markdown("##### Coverage by Framework")
            st.dataframe(scores_df, use_container_width=True, hide_index=True)

            st.markdown("##### Compliance % (per framework)")
            st.bar_chart(scores_df.set_index("Framework")["Compliance %"], height=220)

            st.markdown("---")

        # ---- Existing framework-filtered grouped view ----
        chosen_fw_raw = [FW_LABEL_TO_COL[k] for k in fw_selected] if fw_selected else []
        if chosen_fw_raw:
            mask = findings[chosen_fw_raw].apply(lambda r: any(bool(str(x).strip()) for x in r), axis=1)
            filtered_df = findings.loc[mask].copy()
        else:
            filtered_df = findings.copy()

        # Normalize "Finding Type" (remove numeric parts)
        def _normalize_msg(s: str) -> str:
            return re.sub(r"\d+", "N", str(s))

        filtered_df["Finding Type"] = filtered_df["finding"].apply(_normalize_msg)

        # Group
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

        sort_cols = ["Severity", "Impacted Users"] if "Impacted Users" in grouped.columns else ["Severity"]
        grouped = grouped.sort_values(sort_cols, ascending=[True, False])
        st.dataframe(grouped, use_container_width=True, hide_index=True)

with tab_export:
    if findings.empty:
        st.info("Upload data to generate export.")
    else:
        # Executive summary
        # Existing export buttons
st.download_button("⬇️ Export Findings CSV", csv, file_name="auditguard_findings.csv", mime="text/csv")

# --- Add this block below ---
st.markdown("#### 🧩 Remediation Plan")
remediation_df = findings[["username", "finding_code", "finding"]].copy()
remediation_df["Recommended Action"] = remediation_df["finding_code"].map({
    "MFA_DISABLED_ADMIN": "Enable MFA for admin users (NIST IA-2(1), PCI 8.3.1)",
    "NO_MFA_USER": "Enforce MFA for all user accounts",
    "INACTIVE_60": "Disable or review inactive accounts (>60 days)",
    "STALE_CREDS_90": "Rotate credentials older than 90 days",
    "ORPHANED_ACCOUNT": "Assign manager or disable orphaned accounts",
    "EXCESSIVE_ROLE": "Review elevated access; enforce least privilege"
})
st.dataframe(remediation_df, use_container_width=True, hide_index=True)

fixplan_md = remediation_df.to_markdown(index=False)
st.download_button(
    "⬇️ Download Remediation Plan (.md)",
    fixplan_md.encode("utf-8"),
    file_name="AuditGuard_Remediation_Plan.md",
    mime="text/markdown"
)

# Existing legend block continues
with st.expander("🗂️ Framework Legend"):
    ...

        total = findings["username"].nunique()
        high = findings.query("severity == 'High'")["username"].nunique()
        med = findings.query("severity == 'Medium'")["username"].nunique()
        low = findings.query("severity == 'Low'")["username"].nunique()
        summary = f"""# AuditGuard – Executive Summary

- **Accounts analyzed:** {total}
- **High-risk users:** {int(high)}
- **Medium-risk users:** {int(med)}
- **Low-risk users:** {int(low)}

**What this means:** Immediate focus on MFA for admins, credential rotation >90 days, and orphaned accounts. AuditGuard maps these to NIST, ISO 27001, PCI DSS, and SOC 2 to support evidence and remediation plans.

*Generated by AuditGuard demo.*
"""
        st.markdown("#### Executive Summary (Markdown)")
        st.code(summary, language="markdown")
        st.download_button("⬇️ Download Executive Summary (.md)", summary.encode("utf-8"), file_name="AuditGuard_Executive_Summary.md", mime="text/markdown")

        # Findings CSV export
        csv = findings.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export Findings CSV", csv, file_name="auditguard_findings.csv", mime="text/csv")

        # Coverage export (Week 15)
        scores_df = compute_framework_scores(findings)
        coverage_csv = scores_df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export Coverage Scores (CSV)", coverage_csv, file_name="auditguard_framework_coverage.csv", mime="text/csv")

        with st.expander("🗂️ Framework Legend"):
            st.markdown("""
- **NIST 800-53 Rev.5** (e.g., AC-2, AC-6, IA-2, IA-5)  
- **ISO/IEC 27001:2022** (Annex A, e.g., A.9.x)  
- **PCI DSS v4.0** (Req. 7–8 user access & auth)  
- **SOC 2** (Common Criteria CC6.x)
            """)

# Footer note
st.markdown('<div class="ag-note">Built by Tanny • AuditGuard (enterprise demo)</div>', unsafe_allow_html=True)
