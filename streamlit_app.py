# streamlit_app.py  — AuditGuard (IAM Audit Readiness Dashboard)
import streamlit as st
import pandas as pd
from io import StringIO
from datetime import datetime
from typing import List, Dict, Tuple

st.set_page_config(page_title="AuditGuard – IAM Audit Readiness", page_icon="🛡️", layout="wide")
st.title("🛡️ AuditGuard – IAM Audit Readiness Dashboard")
st.caption("Prototype for real-time IAM control visibility and framework mapping (NIST, ISO 27001, PCI DSS, SOC 2)")

# ------------- Helpers: Control mappings & risk logic -----------------

CONTROL_MAP = {
    "MFA_DISABLED_ADMIN": {
        "description": "Admin account with MFA disabled",
        "nist": ["AC-2(1)", "IA-2(1)"],
        "iso": ["A.9.2.3", "A.9.4.2"],
        "pci": ["8.3.1", "8.4.2"],
        "soc2": ["CC6.1", "CC6.6"],
        "severity": "High"
    },
    "NO_MFA_USER": {
        "description": "User without MFA enabled",
        "nist": ["IA-2(1)"],
        "iso": ["A.9.4.2"],
        "pci": ["8.3.1"],
        "soc2": ["CC6.6"],
        "severity": "Medium"
    },
    "INACTIVE_60": {
        "description": "User inactive > 60 days",
        "nist": ["AC-2(3)"],
        "iso": ["A.9.2.6"],
        "pci": ["8.2.6"],
        "soc2": ["CC6.2"],
        "severity": "Medium"
    },
    "STALE_CREDS_90": {
        "description": "Credentials not rotated > 90 days",
        "nist": ["IA-5(1)"],
        "iso": ["A.9.2.4"],
        "pci": ["8.3.6"],
        "soc2": ["CC6.6"],
        "severity": "High"
    },
    "ORPHANED_ACCOUNT": {
        "description": "Account without active owner/manager",
        "nist": ["AC-2"],
        "iso": ["A.9.2.1"],
        "pci": ["7.1.2"],
        "soc2": ["CC6.1"],
        "severity": "High"
    },
    "EXCESSIVE_ROLE": {
        "description": "Elevated role not justified (non-admin in admin group)",
        "nist": ["AC-6"],
        "iso": ["A.9.1.2"],
        "pci": ["7.1.1"],
        "soc2": ["CC6.3"],
        "severity": "Medium"
    }
}

def _parse_bool(v):
    if pd.isna(v): return None
    s = str(v).strip().lower()
    return True if s in ("true","t","yes","y","1","enabled","active","on") else False if s in ("false","f","no","n","0","disabled","inactive","off") else None

def _parse_date(v):
    if pd.isna(v) or str(v).strip()=="":
        return None
    for fmt in ("%Y-%m-%d","%Y/%m/%d","%m/%d/%Y","%d/%m/%Y","%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(str(v), fmt)
        except Exception:
            continue
    return None

# ------------- Normalizers: bring different CSVs to one schema --------
# Target schema columns:
# username, email, role, is_admin (bool), mfa_enabled (bool),
# last_login (datetime or None), creds_last_rotated (datetime or None), has_manager (bool)

def normalize_salesforce(df: pd.DataFrame) -> pd.DataFrame:
    # Common Salesforce export columns: Username, Email, Profile, UserRole, IsActive, LastLoginDate, ManagerId
    return pd.DataFrame({
        "username": df.get("Username", df.get("UserName")),
        "email": df.get("Email"),
        "role": df.get("Profile", df.get("UserRole")),
        "is_admin": df.get("Profile", "").astype(str).str.contains("System Administrator", case=False, na=False),
        "mfa_enabled": df.get("IsMFAEnabled", df.get("MfaEnabled", False)).apply(_parse_bool),
        "last_login": df.get("LastLoginDate").apply(_parse_date),
        "creds_last_rotated": None,  # not in typical SF user export
        "has_manager": df.get("ManagerId").notna() if "ManagerId" in df.columns else True
    })

def normalize_aws_iam(df: pd.DataFrame) -> pd.DataFrame:
    # AWS Credential Report columns (examples): user, password_enabled, mfa_active, password_last_changed, access_key_1_last_rotated, arn, user_creation_time, group_list
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
        "has_manager": True  # IAM users typically not modeled with managers
    })

def normalize_azure_entra(df: pd.DataFrame) -> pd.DataFrame:
    # Typical bulk export columns: User principal name, Display name, Last sign-in date, MFA State, Roles
    return pd.DataFrame({
        "username": df.get("User principal name", df.get("UserPrincipalName")),
        "email": df.get("User principal name", df.get("UserPrincipalName")),
        "role": df.get("Roles", df.get("Directory roles")),
        "is_admin": df.get("Roles", "").astype(str).str.contains("Global Administrator|Privileged", case=False, na=False),
        "mfa_enabled": df.get("MFA State", df.get("MFA")).apply(_parse_bool),
        "last_login": df.get("Last sign-in date", df.get("LastSignInDate")).apply(_parse_date),
        "creds_last_rotated": None,
        "has_manager": df.get("Manager").notna() if "Manager" in df.columns else True
    })

def normalize_generic(df: pd.DataFrame) -> pd.DataFrame:
    # Expect columns close to the target schema; we best-effort map
    return pd.DataFrame({
        "username": df.get("username", df.get("user")),
        "email": df.get("email"),
        "role": df.get("role", df.get("group")),
        "is_admin": df.get("is_admin", df.get("admin")).apply(_parse_bool) if "is_admin" in df.columns or "admin" in df.columns else False,
        "mfa_enabled": df.get("mfa_enabled", df.get("MFA")).apply(_parse_bool) if "mfa_enabled" in df.columns or "MFA" in df.columns else None,
        "last_login": df.get("last_login").apply(_parse_date) if "last_login" in df.columns else None,
        "creds_last_rotated": df.get("creds_last_rotated").apply(_parse_date) if "creds_last_rotated" in df.columns else None,
        "has_manager": df.get("has_manager").apply(_parse_bool) if "has_manager" in df.columns else True
    })

NORMALIZERS = {
    "Salesforce": normalize_salesforce,
    "AWS IAM": normalize_aws_iam,
    "Azure Entra ID": normalize_azure_entra,
    "Generic CSV": normalize_generic
}

# ---------------- Risk classification ----------------

def classify_row(row) -> List[Tuple[str, str]]:
    """Return list of (finding_code, reason) for the row."""
    findings = []

    is_admin = bool(row.get("is_admin") or (row.get("role") and "admin" in str(row.get("role")).lower()))
    mfa = row.get("mfa_enabled")
    last_login = row.get("last_login")
    creds_rot = row.get("creds_last_rotated")
    has_manager = row.get("has_manager", True)

    # MFA conditions
    if is_admin and (mfa is False or mfa is None):
        findings.append(("MFA_DISABLED_ADMIN", "Admin without MFA"))
    elif mfa is False:
        findings.append(("NO_MFA_USER", "User without MFA"))

    # Inactivity
    if isinstance(last_login, datetime):
        days = (datetime.now() - last_login).days
        if days > 60:
            findings.append(("INACTIVE_60", f"Inactive for {days} days"))
    else:
        findings.append(("INACTIVE_60", "No last_login timestamp available"))

    # Credential rotation
    if isinstance(creds_rot, datetime):
        days = (datetime.now() - creds_rot).days
        if days > 90:
            findings.append(("STALE_CREDS_90", f"Credentials last rotated {days} days ago"))

    # Ownership / orphaned
    if has_manager is False:
        findings.append(("ORPHANED_ACCOUNT", "No active manager assigned"))

    # Excessive role example
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
                "soc2": ""
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
                    "soc2": ", ".join(meta["soc2"])
                })
    return pd.DataFrame(rows)

# ----------------------------- UI ------------------------------------

st.header("📥 Upload IAM Exports")
st.write("Upload CSVs from **Salesforce**, **AWS IAM**, **Azure Entra ID**, or a **Generic CSV** and select the correct source so AuditGuard can normalize the fields.")

uploads = []
cols = st.columns(3)
for i in range(3):
    with cols[i]:
        src = st.selectbox(f"Source #{i+1}", ["—", "Salesforce", "AWS IAM", "Azure Entra ID", "Generic CSV"], key=f"src{i}")
        file = st.file_uploader(f"Upload CSV #{i+1}", type=["csv"], key=f"file{i}")
        if src != "—" and file is not None:
            uploads.append((src, file))

with st.expander("Required / Typical Columns by Source"):
    st.markdown("""
- **Salesforce:** `Username, Email, Profile, UserRole, IsMFAEnabled, LastLoginDate, ManagerId`  
- **AWS IAM (Credential Report):** `user, mfa_active, password_last_changed, access_key_1_last_rotated, group_list, password_last_used`  
- **Azure Entra ID:** `User principal name, Roles, MFA State, Last sign-in date, Manager`  
- **Generic CSV (any app):** `username, email, role, is_admin, mfa_enabled, last_login, creds_last_rotated, has_manager`
""")

if not uploads:
    st.info("Upload at least one CSV to continue.")
    st.stop()

normalized_frames = []
for src, file in uploads:
    df_raw = pd.read_csv(file)
    norm = NORMALIZERS[src](df_raw)
    norm["source"] = src
    normalized_frames.append(norm)

data = pd.concat(normalized_frames, ignore_index=True).fillna({"mfa_enabled": False, "has_manager": True})
findings = expand_findings(data)

# ---- Summary metrics
st.markdown("---")
st.header("📊 Posture Summary")

total_accts = findings["username"].nunique()
high = findings.query("severity == 'High'")["username"].nunique()
medium = findings.query("severity == 'Medium'")["username"].nunique()

m1, m2, m3 = st.columns(3)
m1.metric("Accounts analyzed", total_accts)
m2.metric("Accounts with High-risk findings", high)
m3.metric("Accounts with Medium-risk findings", medium)

# ================== NEW: Framework filter + Grouped summary (drop-in) ==================
# Place this block ABOVE your "Findings table" section.

# Raw framework columns in your 'findings' dataframe
_FW_RAW = {"NIST 800-53": "nist", "ISO 27001": "iso", "PCI DSS": "pci", "SOC 2": "soc2"}
_BASE_COLS = [
    "source", "finding_code", "finding", "severity",
    "username", "last_login", "creds_last_rotated", "has_manager"
]

st.subheader("🧭 Findings — filters & summary")

# 1) Framework column toggle
chosen_fw_labels = st.multiselect(
    "Filter by framework (affects the summary and filtered detail below)",
    options=list(_FW_RAW.keys()),
    default=list(_FW_RAW.keys()),
)
chosen_fw_raw = [_FW_RAW[k] for k in chosen_fw_labels] if chosen_fw_labels else []

# 2) Build a filtered detail view (only rows that have ANY mapping in selected frameworks)
if chosen_fw_raw:
    _mask_has_mapping = findings[chosen_fw_raw].apply(
        lambda r: any(bool(str(x).strip()) for x in r), axis=1
    )
    filtered_df = findings.loc[_mask_has_mapping].copy()
else:
    # If nothing selected, show all (summary still useful)
    filtered_df = findings.copy()

# 3) Grouped summary by finding type (counts, sources, and mapped controls)
_group_cols = ["finding_code", "finding", "severity"]
# Pick only present cols to avoid KeyErrors
_present_fw_raw = [c for c in _FW_RAW.values() if c in filtered_df.columns]

def _join_uniq(series: pd.Series) -> str:
    vals = [str(x).strip() for x in series if str(x).strip()]
    return ", ".join(sorted(set(vals)))

grouped = (
    filtered_df.groupby(_group_cols, dropna=False)
    .agg({
        "username": "nunique",                    # unique impacted users
        "source": _join_uniq,                     # which sources
        **{c: _join_uniq for c in _present_fw_raw}# framework mappings
    })
    .rename(columns={"username": "Impacted Users", "source": "Sources"})
    .reset_index()
    .sort_values(["severity", "Impacted Users"], ascending=[True, False])
)

# 4) Show in tabs: summary vs. filtered detail (keeps your original full table below intact)
tab_sum, tab_filt = st.tabs(["📊 Grouped by finding", "📄 Filtered rows"])

with tab_sum:
    st.caption("One row per finding type — how many users, which sources, and which controls apply.")

    # 1) Pretty-rename framework columns present in the grouped frame
    #    (raw -> display labels)
    pretty_grouped = grouped.rename(
        columns={v: k for k, v in _FW_RAW.items() if v in grouped.columns}
    )

    # 2) Also pretty-rename base columns
    pretty_grouped = pretty_grouped.rename(columns={
        "finding_code": "Finding Code",
        "finding": "Finding",
        "severity": "Severity",
        "source": "Sources",            # if present for any reason
        "username": "Impacted Users"    # guard if agg rename didn’t catch
    })

    # 3) Build desired display list *after* rename
    desired_fw_cols = [label for label in _FW_RAW.keys() if label in pretty_grouped.columns]
    desired_cols = ["Finding Code", "Finding", "Severity", "Impacted Users", "Sources"] + desired_fw_cols

    # 4) Only keep columns that actually exist (prevents KeyError)
    show_cols = [c for c in desired_cols if c in pretty_grouped.columns]

    if not show_cols:
        # Fallback: show whatever columns are available
        st.info("No grouped columns found for the current selection. Showing available columns.")
        st.dataframe(pretty_grouped, use_container_width=True, hide_index=True)
    else:
        st.dataframe(pretty_grouped[show_cols], use_container_width=True, hide_index=True)


with tab_filt:
    st.caption("Detail rows restricted to findings mapped in the selected framework(s).")
    # Show only base cols + the selected framework columns for clarity
    _detail_cols = [c for c in _BASE_COLS if c in filtered_df.columns] + chosen_fw_raw
    pretty_detail = filtered_df[_detail_cols].rename(columns={
        "source": "Source",
        "finding_code": "Finding Code",
        "finding": "Finding",
        "severity": "Severity",
        "username": "Username",
        "last_login": "Last Login",
        "creds_last_rotated": "Creds Rotated",
        "has_manager": "Has Manager",
        **{v: k for k, v in _FW_RAW.items()}
    })
    st.dataframe(pretty_detail, use_container_width=True, hide_index=True)
# ================== /NEW =================================================================

# ---- Findings table
st.markdown("### 🔎 Findings mapped to frameworks")
def _color_sev(val):
    return f"background-color: {'#ff4d4d' if val=='High' else '#ffa64d' if val=='Medium' else '#85e085'}"

styled = findings.rename(columns={
    "username":"Username","email":"Email","role":"Role","is_admin":"Is Admin",
    "mfa_enabled":"MFA Enabled","last_login":"Last Login","creds_last_rotated":"Creds Rotated",
    "has_manager":"Has Manager","severity":"Severity","finding":"Finding",
    "nist":"NIST 800-53","iso":"ISO 27001","pci":"PCI DSS","soc2":"SOC 2","source":"Source"
})

st.dataframe(styled.style.applymap(_color_sev, subset=["Severity"]), use_container_width=True, height=420)

# ---- Download evidence
csv = findings.to_csv(index=False).encode("utf-8")
st.download_button("⬇️ Export Findings CSV (evidence)", csv, file_name="auditguard_findings.csv", mime="text/csv")

# ---- Notes / legend
with st.expander("🗂️ Framework Legend"):
    st.markdown("""
- **NIST 800-53 Rev.5** (e.g., AC-2, AC-6, IA-2, IA-5)  
- **ISO/IEC 27001:2022** (Annex A, e.g., A.9.x)  
- **PCI DSS v4.0** (Req. 7–8 user access & auth)  
- **SOC 2** (Common Criteria CC6.x)
""")

st.markdown("---")
st.caption("Built by Tanny • AuditGuard prototype (IAM identity & access readiness MSc capstone project)")
