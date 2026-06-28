# app.py
import os
import shutil
import re
import streamlit as st
from schemas import ComplianceState
from pipeline import compliance_pipeline

def highlight_vulnerability_text(text: str) -> str:
    """Highlights critical security vectors and legendary exploit keywords for rapid audit scanning."""
    keywords_red = [
        r"\bRCE\b", r"Remote Code Execution", r"Log4Shell", r"Heartbleed", 
        r"arbitrary code execution", r"denial of service", r"\bDoS\b", r"overflow"
    ]
    keywords_orange = [
        r"information disclosure", r"leak", r"bypass", r"spoofing", r"privilege escalation"
    ]
    
    # Inject HTML styling spans around regex matches
    for kw in keywords_red:
        text = re.sub(kw, lambda m: f"<span style='color:#ff4b4b; font-weight:bold;'>{m.group(0)}</span>", text, flags=re.IGNORECASE)
    for kw in keywords_orange:
        text = re.sub(kw, lambda m: f"<span style='color:#ffa500; font-weight:bold;'>{m.group(0)}</span>", text, flags=re.IGNORECASE)
        
    return text


# Configure global webpage appearance
st.set_page_config(
    page_title="EU Cyber Resilience Act (CRA) Pipeline",
    page_icon="🇪🇺",
    layout="wide"
)

st.title("EU Cyber Resilience Act (CRA) Audit Pipeline")
st.caption("Live Multi-Agent Compliance Scan & Direct Manifest File Upload Platform")

# Setup an isolated workspace path for uploaded manifests
TEMP_WORKSPACE = "./ui_uploaded_workspace"

# ----------------- UI INPUT LAYOUT -----------------
st.subheader("📁 Upload Target Manifest Files")
st.info("Upload one or more manifest files below to evaluate project dependencies live against NVD records.")

# Render 3 adjacent upload zones for C++, Java, and Python
col_py, col_jv, col_cpp = st.columns(3)

with col_py:
    uploaded_requirements = st.file_uploader(
        "Python Environment", 
        type=["txt"], 
        help="Upload a standard requirements.txt file"
    )

with col_jv:
    uploaded_pom = st.file_uploader(
        "Java Project Object Model", 
        type=["xml"], 
        help="Upload a standard pom.xml file"
    )

with col_cpp:
    uploaded_cmake = st.file_uploader(
        "CMake Build System Configuration", 
        type=["txt"], 
        help="Upload a standard CMakeLists.txt file"
    )

# --- EXECUTION ENGINE GATEWAY ---
if st.button("Run Compliance Audit", type="primary"):
    # Ensure at least one file was supplied to prevent blank pipeline evaluation states
    if not (uploaded_requirements or uploaded_pom or uploaded_cmake):
        st.warning("Please upload at least one dependency manifest file before executing the audit.")
    else:
        # Re-initialize a clean workspace directory on every click
        if os.path.exists(TEMP_WORKSPACE):
            shutil.rmtree(TEMP_WORKSPACE)
        os.makedirs(TEMP_WORKSPACE, exist_ok=True)
        
        # Safely flush uploaded buffer contents into exact file names expected by agent regex engines
        if uploaded_requirements:
            with open(os.path.join(TEMP_WORKSPACE, "requirements.txt"), "wb") as f:
                f.write(uploaded_requirements.getbuffer())
                
        if uploaded_pom:
            with open(os.path.join(TEMP_WORKSPACE, "pom.xml"), "wb") as f:
                f.write(uploaded_pom.getbuffer())
                
        if uploaded_cmake:
            with open(os.path.join(TEMP_WORKSPACE, "CMakeLists.txt"), "wb") as f:
                f.write(uploaded_cmake.getbuffer())

        with st.spinner("Executing pipeline agents and querying NVD live registry..."):
            # Construct Pydantic state targeted directly at the isolated workspace folder path
            initial_state = ComplianceState(repository_path=TEMP_WORKSPACE)
            
            # Invoke the LangGraph framework compiled pipeline
            final_output = compliance_pipeline.invoke(initial_state)
            
            # --- RENDER RESULTS BANNER ---
            is_compliant = final_output.get("cra_compliant", False)
            if is_compliant:
                st.success("### ✅ PASS: CONFORMITY CERTIFICATE GRANTED\nCodebase adheres completely to EU Cyber Resilience Act Article 10 regulations.")
            else:
                st.error("### ❌ FAIL: CRITICAL NON-COMPLIANCE DETECTED\nKnown exploitable vulnerabilities exist. This software cannot be legally shipped to the EU market.")
            
            # Layout Presentation Split Containers
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📦 Generated Software Bill of Materials (SBOM)")
                sbom_data = final_output.get("sbom", [])
                if sbom_data:
                    sbom_table = [
                        {
                            "Component": item.name,
                            "Version": item.version,
                            "Language": item.language,
                            "Original Manifest": item.source_file
                        }
                        for item in sbom_data
                    ]
                    st.dataframe(sbom_table, use_container_width=True)
                else:
                    st.info("No software components could be parsed from the supplied manifests.")

                        # --- UPDATE THIS DATA GRID BLOCK INSIDE YOUR APP.PY RUN BLOCK ---
            with col2:
                st.subheader("🛡️ NVD Live Vulnerability Analysis")
                vuln_data = final_output.get("vulnerabilities", [])
                if vuln_data:
                    # Injected CVSS Score right into the interactive data grid display
                    vuln_table = [
                        {
                            "CVE ID": v.cve_id,
                            "Target Package": v.package,
                            "Version": v.version,
                            "CVSS Score": v.cvss_score if v.cvss_score is not None else "N/A",
                            "Severity": v.severity,
                            "Status": "🟢 ALLOWED (WHITELISTED)" if v.whitelisted else ("🛑 BLOCKS SHIPMENT" if v.exploitable else "⚠️ AUDIT TRACKED")
                        }
                        for v in vuln_data
                    ]
                    # Sort by score descending so the worst threats float to the top
                    vuln_table = sorted(vuln_table, key=lambda x: x["CVSS Score"] if isinstance(x["CVSS Score"], float) else 0, reverse=True)
                    st.dataframe(vuln_table, use_container_width=True)
                else:
                    st.success("Zero matching vulnerability vectors detected in NVD database registries.")

            
            if vuln_data:
                st.markdown("---")
                st.subheader("🔍 Interactive Vulnerability Breakdown Feed")
                st.caption("Click on any threat card below to read the full NVD description and see the remediation roadmap.")
                
                                # --- UPDATE THE INTERACTIVE BREAKDOWN FEED INSIDE APP.PY ---
                for v in vuln_data:
                    # Determine indicator color based on vulnerability status
                    if v.whitelisted:
                        border_color = "green"
                        status_banner = f"🟢 ALLOWED OVERRIDE (WHITELISTED)"
                    elif v.exploitable:
                        border_color = "red"
                        status_banner = "🛑 BLOCKS EU SHIPMENT (HIGH/CRITICAL EXPLOIT RISK)"
                    else:
                        border_color = "orange"
                        status_banner = "⚠️ AUDIT TRACKED (LOW/MEDIUM COMPLIANCE RISK)"
                        
                    score_display = f"CVSS: {v.cvss_score}" if v.cvss_score is not None else "CVSS: N/A"
                    
                    with st.expander(f"⚠️ {v.cve_id} — {v.package.upper()} ({v.version}) | {score_display} ({v.severity})"):
                        st.markdown(f"**CRA Regulatory Impact:** {status_banner}")
                        
                        # Render Whitelist justification reason if active
                        if v.whitelisted:
                            st.warning(f"📝 **Approved Compliance Justification:** *{v.whitelist_reason}*")
                        else:
                            st.info(f"💡 **CRA Remediation Patch Advisory:** `{v.recommended_version}`")
                        
                        with st.container(border=True):
                            cleaned_description = highlight_vulnerability_text(v.description)
                            st.markdown(cleaned_description, unsafe_allow_html=True)
