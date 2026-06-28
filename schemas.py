from typing import List, Optional
from pydantic import BaseModel, Field

class Dependency(BaseModel):
    name: str
    version: str
    language: str  # "C++", "Java", or "Python"
    source_file: str

class Vulnerability(BaseModel):
    cve_id: str
    package: str
    version: str
    severity: str
    cvss_score: Optional[float] = None
    description: str
    exploitable: bool
    recommended_version: Optional[str] = None
    whitelisted: bool = False
    whitelist_reason: Optional[str] = None
    

class ComplianceState(BaseModel):
    repository_path: str
    sbom: List[Dependency] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    cra_compliant: Optional[bool] = None
