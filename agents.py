import os
import re
import requests
import time
from typing import Dict, List, Any
from schemas import ComplianceState, Dependency, Vulnerability
import config
import logging
import yaml
from packaging.version import Version, InvalidVersion
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

logger = logging.getLogger(__name__)

def sbom_generator_agent(state: ComplianceState) -> Dict[str, Any]:
    """Scans codebases for Python, Java, and C++ dependency files."""
    detected_dependencies = []
    repo = state.repository_path

    # --- A. PYTHON PARSER (requirements.txt) ---
    req_path = os.path.join(repo, "requirements.txt")
    if os.path.exists(req_path):
        with open(req_path, "r") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    match = re.match(r"^([a-zA-Z0-9_\-]+)\s*==\s*([a-zA-Z0-9\.]+)", line)
                    if match:
                        detected_dependencies.append(Dependency(
                            name=match.group(1).lower().strip(), 
                            version=match.group(2).strip(),
                            language="Python", source_file="requirements.txt"
                        ))

    # --- B. JAVA PARSER (pom.xml) ---
    pom_path = os.path.join(repo, "pom.xml")
    if os.path.exists(pom_path):
        with open(pom_path, "r") as f:
            content = f.read()
            deps = re.findall(r"<dependency>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>", content, re.DOTALL)
            for artifact, version in deps:
                detected_dependencies.append(Dependency(
                    name=artifact.strip().lower(), version=version.strip(),
                    language="Java", source_file="pom.xml"
                ))

    # --- C. C++ PARSER (CMakeLists.txt) ---
    cmake_path = os.path.join(repo, "CMakeLists.txt")
    if os.path.exists(cmake_path):
        with open(cmake_path, "r") as f:
            for line in f:
                match = re.search(r"find_package\s*\(\s*([a-zA-Z0-9_\-]+)\s+([0-9a-zA-Z\.]+)", line, re.IGNORECASE)
                if match:
                    detected_dependencies.append(Dependency(
                        name=match.group(1).lower().strip(), version=match.group(2).strip(),
                        language="C++", source_file="CMakeLists.txt"
                    ))

    return {"sbom": detected_dependencies}


def _clean_version_for_pep440(version_str: str) -> str:
    """Normalizes non-standard versions (like OpenSSL 1.0.1f) into standard components."""
    match = re.match(r"^([0-9\.]+)([a-z])$", version_str.strip().lower())
    if match:
        base_digits = match.group(1)
        letter_pos = str(ord(match.group(2)) - ord('a') + 1)
        return f"{base_digits}.{letter_pos}"
    return version_str


def _version_in_range(version: str, cpe_match: Dict[str, Any]) -> bool:
    """Check if a version falls within a CPE match's vulnerable range."""
    start_incl = cpe_match.get("versionStartIncluding")
    start_excl = cpe_match.get("versionStartExcluding")
    end_incl = cpe_match.get("versionEndIncluding")
    end_excl = cpe_match.get("versionEndExcluding")

    if not any([start_incl, start_excl, end_incl, end_excl]):
        cpe_uri = cpe_match.get("criteria", "")
        parts = cpe_uri.split(":")
        cpe_version = parts[5] if len(parts) > 5 else None
        return cpe_version == version or cpe_version == "*"

    v_clean = _clean_version_for_pep440(version)
    try:
        v = Version(v_clean)
    except InvalidVersion:
        return False

    try:
        if start_incl and v < Version(_clean_version_for_pep440(start_incl)):
            return False
        if start_excl and v <= Version(_clean_version_for_pep440(start_excl)):
            return False
        if end_incl and v > Version(_clean_version_for_pep440(end_incl)):
            return False
        if end_excl and v >= Version(_clean_version_for_pep440(end_excl)):
            return False
    except InvalidVersion:
        return False

    return True


def _cve_affects_version(cve_data: Dict[str, Any], version: str, package_name: str) -> bool:
    """Traverses data configurations confirming software coverage statuses."""
    package_lower = package_name.lower().strip()
    for config_node in cve_data.get("configurations", []):
        for node in config_node.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue

                cpe_uri = cpe_match.get("criteria", "")
                parts = cpe_uri.split(":")
                cpe_product = parts[4].lower() if len(parts) > 4 else ""

                if package_lower != cpe_product and package_lower not in cpe_product:
                    if package_lower == "log4j-core" and cpe_product == "log4j":
                        pass
                    elif package_lower == "requests" and cpe_product in ["requests", "python-requests", "python"]:
                        pass
                    else:
                        continue

                if _version_in_range(version, cpe_match):
                    return True
    return False


def _query_nvd_api(package_name: str, version: str) -> List[Dict[str, Any]]:
    """Queries NVD live API mapping components to deterministic CPE patterns."""
    CPE_PRODUCT_MAP = {
        "django": {"vendor": "djangoproject", "product": "django"},
        "requests": {"vendor": "python", "product": "requests"},
        "openssl": {"vendor": "openssl", "product": "openssl"},
        "log4j-core": {"vendor": "apache", "product": "log4j"}
    }
    
    pkg_key = package_name.lower().strip()
    headers = {"apiKey": config.NVD_API_KEY} if getattr(config, "NVD_API_KEY", None) else {}
    
    if pkg_key in CPE_PRODUCT_MAP:
        vendor = CPE_PRODUCT_MAP[pkg_key]["vendor"]
        product = CPE_PRODUCT_MAP[pkg_key]["product"]
        cpe_string = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        params = {"cpeName": cpe_string, "resultsPerPage": 50}
    else:
        params = {"keywordSearch": package_name, "resultsPerPage": 50}

    session = requests.Session()
    retry_strategy = Retry(
        total=4,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)

    try:
        response = session.get(
            config.NVD_BASE_URL, params=params, headers=headers, timeout=60
        )
        response.raise_for_status()
        data = response.json()
        time.sleep(0.8 if "apiKey" in headers else 5.0)
    except Exception as exc:
        logger.error("NVD API query failed for %s %s: %s", package_name, version, exc)
        raise

    vulns = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})

        # FIRST: Enforce the strict version range match filter gate
        if not _cve_affects_version(cve_data, version, package_name):
            continue  

        # SECOND: Calculate remediation recommendations only for verified vulnerabilities
        recommended_version = "Check Vendor Advisory"
        for config_node in cve_data.get("configurations", []):
            for node in config_node.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", True) and _version_in_range(version, cpe_match):
                        if cpe_match.get("versionEndExcluding"):
                            recommended_version = f"Upgrade to >= {cpe_match['versionEndExcluding']}"
                            break
                        elif cpe_match.get("versionEndIncluding"):
                            recommended_version = f"Upgrade to > {cpe_match['versionEndIncluding']}"
                            break
                if recommended_version != "Check Vendor Advisory":
                    break

        cve_id = cve_data.get("id")
        desc_list = cve_data.get("descriptions", [])
        description = "No description"
        if desc_list:
            description = next(
                (d.get("value") for d in desc_list if d.get("lang") == "en"),
                desc_list[0].get("value", "No description") if len(desc_list) > 0 else "No description"
            )

        metrics = cve_data.get("metrics", {})
        severity = "UNKNOWN"
        cvss_score = None

        if metrics.get("cvssMetricV31") and len(metrics["cvssMetricV31"]) > 0:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss_data["baseSeverity"]
            cvss_score = cvss_data["baseScore"]
        elif metrics.get("cvssMetricV30") and len(metrics["cvssMetricV30"]) > 0:
            cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss_data["baseSeverity"]
            cvss_score = cvss_data["baseScore"]
        elif metrics.get("cvssMetricV2") and len(metrics["cvssMetricV2"]) > 0:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN").upper()
            cvss_score = cvss_data["baseScore"]

        vulns.append({
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": cvss_score,
            "description": description,
            "recommended_version": recommended_version
        })

    return vulns




def vulnerability_scanner_agent(state: ComplianceState) -> Dict[str, Any]:
    """Evaluates the software bill against live threats, checking against an approved whitelist config."""
    found_vulns = []
    
    # Load whitelisted CVE overrides if the configuration file exists
    whitelist_map = {}
    whitelist_path = "cra-whitelist.yaml"
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}
                for entry in config_data.get("whitelisted_cves", []):
                    if "cve_id" in entry and "reason" in entry:
                        whitelist_map[entry["cve_id"].strip().upper()] = entry["reason"]
        except Exception as e:
            logger.error(f"Failed parsing whitelist manifest: {e}")

    for item in state.sbom:
        try:
            nvd_results = _query_nvd_api(item.name, item.version)
            for v in nvd_results:
                cve_upper = v["cve_id"].strip().upper()
                desc_lower = v["description"].lower()
                
                # Check if this specific CVE is whitelisted
                is_whitelisted = cve_upper in whitelist_map
                reason = whitelist_map.get(cve_upper) if is_whitelisted else None
                
                # If it's whitelisted, override exploitable to False so it doesn't block compliance
                is_exploitable = any(kw in desc_lower for kw in config.CRA_EXPLOITABLE_KEYWORDS)
                if is_whitelisted:
                    is_exploitable = False

                found_vulns.append(Vulnerability(
                    cve_id=v["cve_id"],
                    package=item.name,
                    version=item.version,
                    severity=v["severity"],
                    cvss_score=v["cvss_score"],
                    description=v["description"],
                    exploitable=is_exploitable,
                    recommended_version=v["recommended_version"],
                    whitelisted=is_whitelisted,      
                    whitelist_reason=reason         
                ))
        except Exception as e:
            logger.error(f"Skipping scanning execution block for {item.name}: {e}")
            continue
            
    return {"vulnerabilities": found_vulns}


def compliance_officer_agent(state: ComplianceState) -> Dict[str, Any]:
    """Verifies inventory against EU Cyber Resilience Act Article 10 restrictions."""
    has_blocking_vuln = any(v.exploitable for v in state.vulnerabilities)
    has_sbom_items = len(state.sbom) > 0
    
    is_compliant = not has_blocking_vuln and has_sbom_items
    return {"cra_compliant": is_compliant}
