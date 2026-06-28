# main.py
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from schemas import ComplianceState
from pipeline import compliance_pipeline
import config

def create_mock_environment():
    """Generates dummy structure representing a modern polyglot stack with highly vulnerable components."""
    os.makedirs("./mock_app", exist_ok=True)
    
    # 🐍 Python: Django 2.2.0 & Requests 2.28.1
    with open("./mock_app/requirements.txt", "w") as f:
        f.write("django==2.2.0\nrequests==2.28.1\nfastapi==0.100.0")
        
    # ☕ Java: Log4j-core 2.14.1
    with open("./mock_app/pom.xml", "w") as f:
        f.write("<dependency>\n"
                "    <groupId>org.apache.logging.log4j</groupId>\n"
                "    <artifactId>log4j-core</artifactId>\n"
                "    <version>2.14.1</version>\n"
                "</dependency>")
        
    # 🐹 C++: OpenSSL 1.0.1f
    with open("./mock_app/CMakeLists.txt", "w") as f:
        f.write("cmake_minimum_required(VERSION 3.10)\n"
                "project(MockApp CXX)\n"
                "find_package(OpenSSL 1.0.1f REQUIRED)\n")


def run_compliance_audit():
    create_mock_environment()
    
    initial_state = ComplianceState(repository_path="./mock_app")
    final_output = compliance_pipeline.invoke(initial_state)
    
    console = Console()
    console.print("\n")
    
    if final_output["cra_compliant"]:
        status_panel = Panel(
            "[bold green]PASS: CONFORMITY CERTIFICATE GRANTED[/bold green]\n"
            "Codebase adheres completely to EU Cyber Resilience Act Article 10 rules.", 
            title="CRA Compliance Status", border_style="green"
        )
    else:
        status_panel = Panel(
            "[bold red]FAIL: CRITICAL NON-COMPLIANCE DETECTED[/bold red]\n"
            "Known exploitable vulnerabilities exist. Software cannot be legally shipped to the EU market.", 
            title="CRA Compliance Status", border_style="red"
        )
    console.print(status_panel)

    sbom_table = Table(title="Generated Software Bill of Materials (SBOM)", show_header=True, header_style="bold cyan")
    sbom_table.add_column("Component", style="bold")
    sbom_table.add_column("Version")
    sbom_table.add_column("Language")
    sbom_table.add_column("Source Manifest")
    for item in final_output["sbom"]:
        sbom_table.add_row(item.name, item.version, item.language, item.source_file)
    console.print(sbom_table)

    vuln_table = Table(title="NVD Live Vulnerability Analysis", show_header=True, header_style="bold magenta")
    vuln_table.add_column("CVE ID")
    vuln_table.add_column("Target Package")
    vuln_table.add_column("Version")
    vuln_table.add_column("Severity")
    vuln_table.add_column("CRA Exploitable Flag")
    for v in final_output["vulnerabilities"]:
        exp_flag = "[red]YES (BLOCKING)[/red]" if v.exploitable else "[green]NO[/green]"
        vuln_table.add_row(v.cve_id, v.package, v.version, v.severity, exp_flag)
    console.print(vuln_table)

if __name__ == "__main__":
    run_compliance_audit()
