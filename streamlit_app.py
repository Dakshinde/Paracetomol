"""
Streamlit frontend for the Security Scanner.

This is a thin UI client that talks to the Flask backend API
(run.py, default http://127.0.0.1:5000). Start the Flask API first:

    python run.py

Then in another terminal:

    streamlit run streamlit_app.py
"""

import os

import requests
import streamlit as st

API_BASE_URL = os.getenv("SCANNER_API_URL", "http://127.0.0.1:5000")

st.set_page_config(
    page_title="Security Scanner", page_icon="🛡️", layout="wide"
)
st.markdown(
    """
    <style>
    .finding-card {
        border: 1px solid rgba(128, 128, 128, .25);
        border-radius: .75rem;
        padding: 1rem 1.25rem;
        margin: .75rem 0;
    }
    .finding-meta { color: #777; font-size: .9rem; }
    </style>
    """,
    unsafe_allow_html=True,
)
st.title("🛡️ Security Scanner")
st.caption("Find vulnerabilities and exposed secrets, then understand how to fix them.")

tab_upload, tab_git, tab_reports = st.tabs(
    ["📦 Upload ZIP", "🔗 Scan Git Repo", "📊 Past Reports"]
)


def severity_icon(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }.get(severity.lower(), "⚪")


def render_finding(index: int, finding: dict):
    analysis = finding.get("ai_analysis") or {}
    severity = (
        analysis.get("severity_assessment")
        or finding.get("severity")
        or "unknown"
    ).lower()
    tool = str(finding.get("tool", "scanner")).title()
    path = finding.get("path", "Unknown file")
    lines = f"{finding.get('start_line', '?')}-{finding.get('end_line', '?')}"
    title = finding.get("rule_id") or finding.get("description") or "Security finding"

    with st.container(border=True):
        st.markdown(
            f"### {severity_icon(severity)} {title}"
            f"\n\n<span class='finding-meta'>{tool} · `{path}` · lines {lines}"
            f"</span>",
            unsafe_allow_html=True,
        )
        if analysis.get("explanation"):
            st.markdown("**What this means**")
            st.write(analysis["explanation"])
        elif finding.get("message"):
            st.markdown("**What the scanner found**")
            st.write(finding["message"])

        notes = analysis.get("remediation_notes")
        if notes:
            st.markdown("**How to fix it**")
            st.write(notes)

        fixed_code = analysis.get("fixed_code")
        if fixed_code:
            st.markdown("**Suggested change**")
            st.code(fixed_code, language="yaml" if path.endswith((".yml", ".yaml")) else None)

        patch_text = finding.get("patch_text")
        if patch_text:
            with st.expander("Review or download the complete patch"):
                st.caption(
                    "Review this suggestion before applying it. AI-generated "
                    "patches should not be applied blindly."
                )
                st.code(patch_text, language="diff")
                st.download_button(
                    "Download patch",
                    data=patch_text,
                    file_name=f"finding-{index + 1}.patch",
                    mime="text/x-diff",
                    key=f"download_patch_{index}",
                )


def render_report(report: dict):
    findings = report.get("findings", [])
    st.success(
        f"Scan complete — {report.get('total_findings', 0)} finding(s) "
        f"identified in {report.get('duration_seconds', 0)} seconds."
    )
    if report.get("source"):
        st.info(f"Scanned source: {report['source']}")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total findings", report.get("total_findings", 0))
    col2.metric("Semgrep", report.get("semgrep_findings", 0))
    col3.metric("Gitleaks", report.get("gitleaks_findings", 0))
    col4.metric("Duration (s)", report.get("duration_seconds", 0))

    sev = report.get("severity_counts", {})
    st.markdown(
        f"🔴 **{sev.get('critical', 0)}** Critical &nbsp;&nbsp; "
        f"🟠 **{sev.get('high', 0)}** High &nbsp;&nbsp; "
        f"🟡 **{sev.get('medium', 0)}** Medium &nbsp;&nbsp; "
        f"🟢 **{sev.get('low', 0)}** Low",
        unsafe_allow_html=True,
    )

    if report.get("errors"):
        for err in report["errors"]:
            st.warning(err)

    st.subheader("Findings and recommended fixes")
    if not findings:
        st.success("No vulnerabilities or secrets were found.")
    for index, finding in enumerate(findings):
        render_finding(index, finding)


with tab_upload:
    st.subheader("Scan a ZIP project")
    st.write("Upload a project archive and get a plain-English security report.")
    use_ai_upload = st.checkbox("Use Gemini AI analysis", value=True, key="ai_upload")
    uploaded_file = st.file_uploader("Choose a .zip file", type=["zip"])

    if st.button("Scan uploaded project", disabled=uploaded_file is None):
        with st.spinner("Scanning... this can take a minute."):
            files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
            try:
                resp = requests.post(
                    f"{API_BASE_URL}/api/scan/upload",
                    files=files,
                    params={"use_ai": str(use_ai_upload).lower()},
                    timeout=600,
                )
                if resp.ok:
                    st.success("Scan complete.")
                    render_report(resp.json())
                else:
                    st.error(f"Scan failed: {resp.json().get('error', resp.text)}")
            except requests.RequestException as exc:
                st.error(f"Could not reach the API at {API_BASE_URL}: {exc}")

with tab_git:
    st.subheader("Scan a public Git repository")
    st.write("Clone and scan a repository without changing the source repository.")
    use_ai_git = st.checkbox("Use Gemini AI analysis", value=True, key="ai_git")
    repo_url = st.text_input("Repository URL", placeholder="https://github.com/org/repo")
    branch = st.text_input("Branch (optional)", placeholder="main")

    if st.button("Scan repository", disabled=not repo_url):
        with st.spinner("Cloning and scanning... this can take a minute."):
            try:
                resp = requests.post(
                    f"{API_BASE_URL}/api/scan/git",
                    json={
                        "repo_url": repo_url,
                        "branch": branch or None,
                        "use_ai": use_ai_git,
                    },
                    timeout=600,
                )
                if resp.ok:
                    st.success("Scan complete.")
                    render_report(resp.json())
                else:
                    st.error(f"Scan failed: {resp.json().get('error', resp.text)}")
            except requests.RequestException as exc:
                st.error(f"Could not reach the API at {API_BASE_URL}: {exc}")

with tab_reports:
    st.subheader("Past scan reports")
    if st.button("Refresh list"):
        st.rerun()
    try:
        resp = requests.get(f"{API_BASE_URL}/api/reports", timeout=30)
        if resp.ok:
            reports = resp.json()
            if not reports:
                st.info("No reports yet. Run a scan first.")
            for r in reports:
                with st.container(border=True):
                    st.markdown(f"**Scan `{r['scan_id']}`**")
                    st.write(
                        f"{r['total_findings']} findings · "
                        f"🔴 {r['severity_counts'].get('critical', 0)} critical · "
                        f"🟠 {r['severity_counts'].get('high', 0)} high"
                    )
                    if st.button(
                        "Open report",
                        key=f"open_report_{r['scan_id']}",
                    ):
                        detail = requests.get(
                            f"{API_BASE_URL}/api/reports/{r['scan_id']}",
                            timeout=30,
                        )
                        if detail.ok:
                            render_report(detail.json())
                        else:
                            st.error("Could not load this report.")
        else:
            st.error("Could not load reports.")
    except requests.RequestException as exc:
        st.error(f"Could not reach the API at {API_BASE_URL}: {exc}")
