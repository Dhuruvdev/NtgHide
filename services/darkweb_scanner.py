import asyncio
import os
import subprocess
import json
import re
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ThreatLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAR = "CLEAR"
    UNKNOWN = "UNKNOWN"


class DataCategory(Enum):
    PASSWORD = "Password Exposure"
    EMAIL = "Email Leak"
    PERSONAL_INFO = "Personal Information"
    FINANCIAL = "Financial Data"
    CREDENTIALS = "Login Credentials"
    SOCIAL = "Social Media"
    DARKWEB_MENTION = "Dark Web Mention"
    BREACH_DATABASE = "Breach Database Entry"
    UNKNOWN = "Unknown Category"


@dataclass
class ClassifiedResult:
    threat_level: ThreatLevel
    category: DataCategory
    source: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "threat_level": self.threat_level.value,
            "category": self.category.value,
            "source": self.source,
            "description": self.description,
            "details": self.details,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    source: str
    query: str
    found: bool
    data: List[Dict[str, Any]]
    classified_results: List[ClassifiedResult] = field(default_factory=list)
    error: Optional[str] = None
    timestamp: Optional[str] = None
    status: str = "completed"

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "source": self.source,
            "query": self.query,
            "found": self.found,
            "data": self.data,
            "classified_results": [r.to_dict() for r in self.classified_results],
            "error": self.error,
            "timestamp": self.timestamp,
            "status": self.status
        }


def classify_output(output: str, source: str) -> List[ClassifiedResult]:
    results = []
    output_lower = output.lower()
    
    password_patterns = [
        r'password[:\s]+[^\s]+',
        r'pass[:\s]+[^\s]+',
        r'pwd[:\s]+[^\s]+',
        r'hash[:\s]+[a-f0-9]{32,}',
    ]
    
    for pattern in password_patterns:
        if re.search(pattern, output_lower):
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.CRITICAL,
                category=DataCategory.PASSWORD,
                source=source,
                description="Password or hash found in breach data",
                details={"pattern_matched": pattern}
            ))
            break
    
    email_patterns = [
        r'email[:\s]+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    ]
    
    for pattern in email_patterns:
        matches = re.findall(pattern, output)
        if matches:
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.HIGH,
                category=DataCategory.EMAIL,
                source=source,
                description=f"Email address found in {len(matches)} location(s)",
                details={"count": len(matches)}
            ))
            break
    
    credential_indicators = ['username', 'login', 'credential', 'account', 'auth']
    for indicator in credential_indicators:
        if indicator in output_lower:
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.HIGH,
                category=DataCategory.CREDENTIALS,
                source=source,
                description="Login credentials potentially exposed",
                details={"indicator": indicator}
            ))
            break
    
    financial_indicators = ['credit', 'card', 'bank', 'ssn', 'social security', 'cvv', 'account number']
    for indicator in financial_indicators:
        if indicator in output_lower:
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.CRITICAL,
                category=DataCategory.FINANCIAL,
                source=source,
                description="Financial information potentially exposed",
                details={"indicator": indicator}
            ))
            break
    
    personal_indicators = ['address', 'phone', 'dob', 'birth', 'name', 'location']
    for indicator in personal_indicators:
        if indicator in output_lower:
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.MEDIUM,
                category=DataCategory.PERSONAL_INFO,
                source=source,
                description="Personal information found",
                details={"indicator": indicator}
            ))
            break
    
    breach_indicators = ['breach', 'leaked', 'dump', 'compromised', 'exposed']
    for indicator in breach_indicators:
        if indicator in output_lower:
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.HIGH,
                category=DataCategory.BREACH_DATABASE,
                source=source,
                description="Data found in breach database",
                details={"indicator": indicator}
            ))
            break
    
    darkweb_indicators = ['.onion', 'tor', 'hidden service', 'darknet', 'dark web']
    for indicator in darkweb_indicators:
        if indicator in output_lower:
            results.append(ClassifiedResult(
                threat_level=ThreatLevel.HIGH,
                category=DataCategory.DARKWEB_MENTION,
                source=source,
                description="Data mentioned on dark web sources",
                details={"indicator": indicator}
            ))
            break
    
    if not results and output.strip():
        results.append(ClassifiedResult(
            threat_level=ThreatLevel.LOW,
            category=DataCategory.UNKNOWN,
            source=source,
            description="Unclassified data found - manual review recommended",
            details={"raw_length": len(output)}
        ))
    
    return results


class H8MailScanner:
    def __init__(self):
        self.module_path = "Modules/Darkweb Scan/h8mail"

    async def scan(self, email: str) -> ScanResult:
        try:
            results = []
            found = False
            classified = []

            if os.path.exists(self.module_path) and os.listdir(self.module_path):
                process = await asyncio.create_subprocess_exec(
                    "python", "-m", "h8mail", "-t", email, "-j", "/tmp/h8mail_results.json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.module_path
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

                output = ""
                if stdout:
                    output = stdout.decode()
                if stderr:
                    output += stderr.decode()

                if output.strip():
                    if "breach" in output.lower() or "found" in output.lower() or "password" in output.lower():
                        found = True
                        classified = classify_output(output, "h8mail")
                    results.append({"raw_output": output})
            else:
                return ScanResult(
                    source="h8mail",
                    query=email,
                    found=False,
                    data=[],
                    error="Module not installed - add h8mail to Modules/Darkweb Scan/h8mail",
                    status="error"
                )

            return ScanResult(
                source="h8mail",
                query=email,
                found=found,
                data=results,
                classified_results=classified,
                status="completed"
            )
        except asyncio.TimeoutError:
            return ScanResult(
                source="h8mail",
                query=email,
                found=False,
                data=[],
                error="Scan timed out after 60 seconds",
                status="timeout"
            )
        except Exception as e:
            return ScanResult(
                source="h8mail",
                query=email,
                found=False,
                data=[],
                error=str(e),
                status="error"
            )


class TorCrawlScanner:
    def __init__(self):
        self.module_path = "Modules/Darkweb Scan/TorCrawl.py"

    async def scan(self, query: str) -> ScanResult:
        try:
            results = []
            found = False
            classified = []

            if os.path.exists(self.module_path) and os.listdir(self.module_path):
                process = await asyncio.create_subprocess_exec(
                    "python", "torcrawl.py",
                    "-v",
                    "-u", f"https://ahmia.fi/search/?q={query}",
                    "-c",
                    "-d", "1",
                    "-e",
                    "-y", "1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.module_path
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)

                output = ""
                if stdout:
                    output = stdout.decode()
                if stderr:
                    output += stderr.decode()

                if output.strip():
                    if query.lower() in output.lower() or "found" in output.lower():
                        found = True
                        classified = classify_output(output, "TorCrawl")
                        classified.append(ClassifiedResult(
                            threat_level=ThreatLevel.HIGH,
                            category=DataCategory.DARKWEB_MENTION,
                            source="TorCrawl",
                            description="Query found on dark web search engine results",
                            details={"search_url": f"https://ahmia.fi/search/?q={query}"}
                        ))
                    results.append({"raw_output": output, "search_url": f"https://ahmia.fi/search/?q={query}"})
            else:
                return ScanResult(
                    source="TorCrawl",
                    query=query,
                    found=False,
                    data=[],
                    error="Module not installed - add TorCrawl to Modules/Darkweb Scan/TorCrawl.py",
                    status="error"
                )

            return ScanResult(
                source="TorCrawl",
                query=query,
                found=found,
                data=results,
                classified_results=classified,
                status="completed"
            )
        except asyncio.TimeoutError:
            return ScanResult(
                source="TorCrawl",
                query=query,
                found=False,
                data=[],
                error="Scan timed out after 120 seconds",
                status="timeout"
            )
        except Exception as e:
            return ScanResult(
                source="TorCrawl",
                query=query,
                found=False,
                data=[],
                error=str(e),
                status="error"
            )


class WhatBreachScanner:
    def __init__(self):
        self.module_path = "Modules/Darkweb Scan/WhatBreach"

    async def scan(self, email: str) -> ScanResult:
        try:
            results = []
            found = False
            classified = []

            if os.path.exists(self.module_path) and os.listdir(self.module_path):
                process = await asyncio.create_subprocess_exec(
                    "python", "whatbreach.py", "-e", email,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.module_path
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

                if stdout:
                    output = stdout.decode()
                    if "breach" in output.lower() or "found" in output.lower():
                        found = True
                        classified = classify_output(output, "WhatBreach")
                        results.append({"raw_output": output})
            else:
                return ScanResult(
                    source="WhatBreach",
                    query=email,
                    found=False,
                    data=[],
                    error="Module not installed - add WhatBreach to Modules/Darkweb Scan/WhatBreach",
                    status="error"
                )

            return ScanResult(
                source="WhatBreach",
                query=email,
                found=found,
                data=results,
                classified_results=classified,
                status="completed"
            )
        except asyncio.TimeoutError:
            return ScanResult(
                source="WhatBreach",
                query=email,
                found=False,
                data=[],
                error="Scan timed out after 60 seconds",
                status="timeout"
            )
        except Exception as e:
            return ScanResult(
                source="WhatBreach",
                query=email,
                found=False,
                data=[],
                error=str(e),
                status="error"
            )


class DarkwebScannerService:
    def __init__(self):
        self.h8mail = H8MailScanner()
        self.torcrawl = TorCrawlScanner()
        self.whatbreach = WhatBreachScanner()

    def _calculate_overall_threat(self, classified_results: List[ClassifiedResult]) -> str:
        if not classified_results:
            return ThreatLevel.CLEAR.value
        
        threat_priority = {
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.HIGH: 3,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 1,
            ThreatLevel.CLEAR: 0,
            ThreatLevel.UNKNOWN: 0
        }
        
        max_threat = max(classified_results, key=lambda x: threat_priority.get(x.threat_level, 0))
        return max_threat.threat_level.value

    def _group_by_category(self, classified_results: List[ClassifiedResult]) -> Dict[str, List[Dict]]:
        grouped = {}
        for result in classified_results:
            category = result.category.value
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(result.to_dict())
        return grouped

    async def scan_all(self, query: str) -> Dict[str, Any]:
        tasks = [
            self.h8mail.scan(query),
            self.torcrawl.scan(query),
            self.whatbreach.scan(query)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_classified = []
        combined_results: Dict[str, Any] = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "sources": [],
            "total_found": 0,
            "overall_threat_level": ThreatLevel.CLEAR.value,
            "classified_findings": {},
            "summary": {
                "breaches_detected": False,
                "darkweb_mentions": False,
                "data_exposed": False,
                "passwords_found": False,
                "financial_data_exposed": False,
                "credentials_leaked": False,
                "threat_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }
            },
            "recommendations": []
        }

        for result in results:
            if isinstance(result, BaseException):
                combined_results["sources"].append({
                    "source": "Unknown",
                    "error": str(result),
                    "found": False,
                    "data": [],
                    "classified_results": [],
                    "status": "error"
                })
            elif isinstance(result, ScanResult):
                combined_results["sources"].append(result.to_dict())
                all_classified.extend(result.classified_results)
                
                if result.found:
                    combined_results["total_found"] += 1
                    if result.source in ["h8mail", "WhatBreach"]:
                        combined_results["summary"]["breaches_detected"] = True
                    if result.source == "TorCrawl":
                        combined_results["summary"]["darkweb_mentions"] = True
                
                for cr in result.classified_results:
                    if cr.category == DataCategory.PASSWORD:
                        combined_results["summary"]["passwords_found"] = True
                    if cr.category == DataCategory.FINANCIAL:
                        combined_results["summary"]["financial_data_exposed"] = True
                    if cr.category == DataCategory.CREDENTIALS:
                        combined_results["summary"]["credentials_leaked"] = True
                    
                    if cr.threat_level.value in combined_results["summary"]["threat_breakdown"]:
                        combined_results["summary"]["threat_breakdown"][cr.threat_level.value] += 1

        if combined_results["total_found"] > 0:
            combined_results["summary"]["data_exposed"] = True

        combined_results["overall_threat_level"] = self._calculate_overall_threat(all_classified)
        combined_results["classified_findings"] = self._group_by_category(all_classified)
        
        recommendations = []
        if combined_results["summary"]["passwords_found"]:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Change all passwords immediately for affected accounts"
            })
        if combined_results["summary"]["credentials_leaked"]:
            recommendations.append({
                "priority": "HIGH",
                "action": "Enable two-factor authentication on all accounts"
            })
        if combined_results["summary"]["financial_data_exposed"]:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Contact your bank and monitor for fraudulent activity"
            })
        if combined_results["summary"]["darkweb_mentions"]:
            recommendations.append({
                "priority": "HIGH",
                "action": "Monitor dark web mentions regularly and consider identity theft protection"
            })
        if combined_results["summary"]["breaches_detected"]:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Review all accounts associated with this email for unauthorized access"
            })
        
        combined_results["recommendations"] = recommendations

        return combined_results


darkweb_service = DarkwebScannerService()
