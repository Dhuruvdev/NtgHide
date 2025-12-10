import asyncio
import os
import httpx
import hashlib
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ThreatLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAR = "CLEAR"


class DataCategory(Enum):
    PASSWORD = "Password Exposure"
    EMAIL = "Email Leak"
    PERSONAL_INFO = "Personal Information"
    FINANCIAL = "Financial Data"
    CREDENTIALS = "Login Credentials"
    PHONE = "Phone Number"
    ADDRESS = "Physical Address"
    SOCIAL_MEDIA = "Social Media"
    BREACH_DATABASE = "Data Breach"


@dataclass
class BreachInfo:
    name: str
    title: str
    domain: str
    breach_date: str
    pwn_count: int
    description: str
    data_classes: List[str]
    is_verified: bool
    logo_path: Optional[str] = None

    def to_dict(self):
        return {
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "pwn_count": self.pwn_count,
            "description": self.description,
            "data_classes": self.data_classes,
            "is_verified": self.is_verified,
            "logo_path": self.logo_path
        }


@dataclass
class ClassifiedResult:
    threat_level: ThreatLevel
    category: DataCategory
    source: str
    source_domain: str
    description: str
    breach_date: str
    records_affected: int
    data_types: List[str]
    is_verified: bool
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
            "source_domain": self.source_domain,
            "description": self.description,
            "breach_date": self.breach_date,
            "records_affected": self.records_affected,
            "data_types": self.data_types,
            "is_verified": self.is_verified,
            "details": self.details,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    source: str
    query: str
    found: bool
    breaches: List[BreachInfo] = field(default_factory=list)
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
            "breaches": [b.to_dict() for b in self.breaches],
            "classified_results": [r.to_dict() for r in self.classified_results],
            "error": self.error,
            "timestamp": self.timestamp,
            "status": self.status
        }


def determine_threat_level(data_classes: List[str]) -> ThreatLevel:
    critical_types = ['passwords', 'credit cards', 'bank account numbers', 'credit card cvv', 
                      'social security numbers', 'partial credit card data', 'financial data']
    high_types = ['email addresses', 'usernames', 'phone numbers', 'ip addresses', 
                  'dates of birth', 'security questions and answers']
    medium_types = ['names', 'physical addresses', 'employers', 'job titles', 
                    'government issued ids', 'passport numbers']
    
    data_lower = [d.lower() for d in data_classes]
    
    for ct in critical_types:
        if ct in data_lower:
            return ThreatLevel.CRITICAL
    
    for ht in high_types:
        if ht in data_lower:
            return ThreatLevel.HIGH
    
    for mt in medium_types:
        if mt in data_lower:
            return ThreatLevel.MEDIUM
    
    return ThreatLevel.LOW


def determine_category(data_classes: List[str]) -> DataCategory:
    data_lower = [d.lower() for d in data_classes]
    
    if any(x in data_lower for x in ['passwords', 'password hints', 'password strengths']):
        return DataCategory.PASSWORD
    if any(x in data_lower for x in ['credit cards', 'bank account numbers', 'credit card cvv', 'financial data']):
        return DataCategory.FINANCIAL
    if any(x in data_lower for x in ['usernames', 'email addresses']):
        return DataCategory.CREDENTIALS
    if any(x in data_lower for x in ['phone numbers', 'cellular network names']):
        return DataCategory.PHONE
    if any(x in data_lower for x in ['physical addresses', 'geographic locations']):
        return DataCategory.ADDRESS
    if any(x in data_lower for x in ['social media profiles', 'social connections']):
        return DataCategory.SOCIAL_MEDIA
    
    return DataCategory.BREACH_DATABASE


class HIBPScanner:
    """Have I Been Pwned API Scanner - Real breach database"""
    
    def __init__(self):
        self.api_key = os.environ.get('HIBP_API_KEY', '')
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.user_agent = "CensoredScanner-BreachCheck"
    
    async def scan(self, email: str) -> ScanResult:
        if not self.api_key:
            return ScanResult(
                source="Have I Been Pwned",
                query=email,
                found=False,
                error="HIBP API key required. Get one at haveibeenpwned.com/API/Key",
                status="api_key_required"
            )
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "hibp-api-key": self.api_key,
                    "user-agent": self.user_agent
                }
                
                response = await client.get(
                    f"{self.base_url}/breachedaccount/{email}",
                    headers=headers,
                    params={"truncateResponse": "false"}
                )
                
                if response.status_code == 404:
                    return ScanResult(
                        source="Have I Been Pwned",
                        query=email,
                        found=False,
                        status="completed"
                    )
                
                if response.status_code == 401:
                    return ScanResult(
                        source="Have I Been Pwned",
                        query=email,
                        found=False,
                        error="Invalid API key",
                        status="auth_error"
                    )
                
                if response.status_code == 429:
                    return ScanResult(
                        source="Have I Been Pwned",
                        query=email,
                        found=False,
                        error="Rate limited - please try again later",
                        status="rate_limited"
                    )
                
                if response.status_code == 200:
                    breaches_data = response.json()
                    breaches = []
                    classified = []
                    
                    for breach in breaches_data:
                        breach_info = BreachInfo(
                            name=breach.get("Name", "Unknown"),
                            title=breach.get("Title", "Unknown Breach"),
                            domain=breach.get("Domain", "unknown"),
                            breach_date=breach.get("BreachDate", "Unknown"),
                            pwn_count=breach.get("PwnCount", 0),
                            description=breach.get("Description", ""),
                            data_classes=breach.get("DataClasses", []),
                            is_verified=breach.get("IsVerified", False),
                            logo_path=f"https://haveibeenpwned.com/Content/Images/PwnedLogos/{breach.get('Name', '')}.png"
                        )
                        breaches.append(breach_info)
                        
                        threat_level = determine_threat_level(breach_info.data_classes)
                        category = determine_category(breach_info.data_classes)
                        
                        clean_desc = re.sub('<[^<]+?>', '', breach_info.description)
                        if len(clean_desc) > 200:
                            clean_desc = clean_desc[:200] + "..."
                        
                        classified.append(ClassifiedResult(
                            threat_level=threat_level,
                            category=category,
                            source=breach_info.title,
                            source_domain=breach_info.domain,
                            description=clean_desc,
                            breach_date=breach_info.breach_date,
                            records_affected=breach_info.pwn_count,
                            data_types=breach_info.data_classes,
                            is_verified=breach_info.is_verified,
                            details={"verified": breach_info.is_verified}
                        ))
                    
                    return ScanResult(
                        source="Have I Been Pwned",
                        query=email,
                        found=True,
                        breaches=breaches,
                        classified_results=classified,
                        status="completed"
                    )
                
                return ScanResult(
                    source="Have I Been Pwned",
                    query=email,
                    found=False,
                    error=f"API error: {response.status_code}",
                    status="error"
                )
                
        except httpx.TimeoutException:
            return ScanResult(
                source="Have I Been Pwned",
                query=email,
                found=False,
                error="Request timed out",
                status="timeout"
            )
        except Exception as e:
            return ScanResult(
                source="Have I Been Pwned",
                query=email,
                found=False,
                error=str(e),
                status="error"
            )


class PwnedPasswordsScanner:
    """Free Pwned Passwords API - No API key required"""
    
    async def check_password(self, password: str) -> Dict[str, Any]:
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
                
                if response.status_code == 200:
                    hashes = response.text.split('\n')
                    for h in hashes:
                        parts = h.strip().split(':')
                        if len(parts) == 2 and parts[0] == suffix:
                            return {
                                "found": True,
                                "count": int(parts[1]),
                                "message": f"This password has been seen {parts[1]} times in data breaches"
                            }
                    return {"found": False, "count": 0, "message": "Password not found in known breaches"}
                
                return {"found": False, "error": f"API error: {response.status_code}"}
        except Exception as e:
            return {"found": False, "error": str(e)}


class BreachDirectoryScanner:
    """Scans using public breach directory API (no key required)"""
    
    async def scan(self, email: str) -> ScanResult:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    "https://haveibeenpwned.com/api/v3/breaches",
                    headers={"user-agent": "CensoredScanner"}
                )
                
                if response.status_code == 200:
                    all_breaches = response.json()
                    domain = email.split('@')[-1].lower() if '@' in email else ''
                    
                    matching = []
                    for breach in all_breaches:
                        breach_domain = breach.get("Domain", "").lower()
                        if breach_domain and (breach_domain == domain or domain in breach_domain):
                            matching.append(breach)
                    
                    if matching:
                        breaches = []
                        classified = []
                        
                        for breach in matching[:5]:
                            breach_info = BreachInfo(
                                name=breach.get("Name", "Unknown"),
                                title=breach.get("Title", "Unknown"),
                                domain=breach.get("Domain", "unknown"),
                                breach_date=breach.get("BreachDate", "Unknown"),
                                pwn_count=breach.get("PwnCount", 0),
                                description=breach.get("Description", ""),
                                data_classes=breach.get("DataClasses", []),
                                is_verified=breach.get("IsVerified", False)
                            )
                            breaches.append(breach_info)
                            
                            threat_level = determine_threat_level(breach_info.data_classes)
                            
                            classified.append(ClassifiedResult(
                                threat_level=threat_level,
                                category=DataCategory.BREACH_DATABASE,
                                source=breach_info.title,
                                source_domain=breach_info.domain,
                                description=f"Your email domain ({domain}) matches this breached service",
                                breach_date=breach_info.breach_date,
                                records_affected=breach_info.pwn_count,
                                data_types=breach_info.data_classes,
                                is_verified=breach_info.is_verified
                            ))
                        
                        return ScanResult(
                            source="Breach Directory",
                            query=email,
                            found=True,
                            breaches=breaches,
                            classified_results=classified,
                            status="completed"
                        )
                    
                    return ScanResult(
                        source="Breach Directory",
                        query=email,
                        found=False,
                        status="completed"
                    )
                
                return ScanResult(
                    source="Breach Directory",
                    query=email,
                    found=False,
                    error=f"API error: {response.status_code}",
                    status="error"
                )
        except Exception as e:
            return ScanResult(
                source="Breach Directory",
                query=email,
                found=False,
                error=str(e),
                status="error"
            )


class DarkwebScannerService:
    def __init__(self):
        self.hibp = HIBPScanner()
        self.breach_directory = BreachDirectoryScanner()
        self.pwned_passwords = PwnedPasswordsScanner()

    def _calculate_overall_threat(self, classified_results: List[ClassifiedResult]) -> str:
        if not classified_results:
            return ThreatLevel.CLEAR.value
        
        threat_priority = {
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.HIGH: 3,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 1,
            ThreatLevel.CLEAR: 0
        }
        
        max_threat = max(classified_results, key=lambda x: threat_priority.get(x.threat_level, 0))
        return max_threat.threat_level.value

    def _group_by_source(self, classified_results: List[ClassifiedResult]) -> List[Dict]:
        grouped = []
        for result in classified_results:
            grouped.append({
                "source_name": result.source,
                "source_domain": result.source_domain,
                "threat_level": result.threat_level.value,
                "breach_date": result.breach_date,
                "records_affected": result.records_affected,
                "data_types": result.data_types,
                "is_verified": result.is_verified,
                "description": result.description
            })
        return sorted(grouped, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["threat_level"], 4),
            x["source_name"]
        ))

    async def scan_all(self, query: str) -> Dict[str, Any]:
        tasks = [
            self.hibp.scan(query),
            self.breach_directory.scan(query)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_classified = []
        all_breaches = []
        sources_checked = []
        
        combined_results: Dict[str, Any] = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "sources_checked": [],
            "total_breaches": 0,
            "overall_threat_level": ThreatLevel.CLEAR.value,
            "breaches_by_source": [],
            "summary": {
                "breaches_detected": False,
                "passwords_exposed": False,
                "financial_data_exposed": False,
                "personal_info_exposed": False,
                "threat_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                },
                "exposed_data_types": []
            },
            "recommendations": [],
            "api_status": {
                "hibp_configured": bool(os.environ.get('HIBP_API_KEY')),
                "message": ""
            }
        }

        all_data_types = set()

        for result in results:
            if isinstance(result, BaseException):
                sources_checked.append({
                    "source": "Unknown",
                    "status": "error",
                    "error": str(result),
                    "found": False
                })
            elif isinstance(result, ScanResult):
                source_info = {
                    "source": result.source,
                    "status": result.status,
                    "found": result.found,
                    "breach_count": len(result.breaches),
                    "error": result.error
                }
                sources_checked.append(source_info)
                
                all_classified.extend(result.classified_results)
                all_breaches.extend(result.breaches)
                
                if result.found:
                    combined_results["summary"]["breaches_detected"] = True
                
                for cr in result.classified_results:
                    for dt in cr.data_types:
                        all_data_types.add(dt)
                    
                    if cr.category == DataCategory.PASSWORD:
                        combined_results["summary"]["passwords_exposed"] = True
                    if cr.category == DataCategory.FINANCIAL:
                        combined_results["summary"]["financial_data_exposed"] = True
                    if cr.category in [DataCategory.PERSONAL_INFO, DataCategory.ADDRESS, DataCategory.PHONE]:
                        combined_results["summary"]["personal_info_exposed"] = True
                    
                    if cr.threat_level.value in combined_results["summary"]["threat_breakdown"]:
                        combined_results["summary"]["threat_breakdown"][cr.threat_level.value] += 1

        combined_results["sources_checked"] = sources_checked
        combined_results["total_breaches"] = len(all_breaches)
        combined_results["overall_threat_level"] = self._calculate_overall_threat(all_classified)
        combined_results["breaches_by_source"] = self._group_by_source(all_classified)
        combined_results["summary"]["exposed_data_types"] = list(all_data_types)
        
        if not os.environ.get('HIBP_API_KEY'):
            combined_results["api_status"]["message"] = "Add HIBP_API_KEY for full email breach scanning"
        
        recommendations = []
        if combined_results["summary"]["passwords_exposed"]:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "Change passwords immediately for all accounts using this email",
                "icon": "🔐"
            })
        if combined_results["summary"]["financial_data_exposed"]:
            recommendations.append({
                "priority": "CRITICAL", 
                "action": "Monitor bank accounts and consider a credit freeze",
                "icon": "💳"
            })
        if combined_results["summary"]["personal_info_exposed"]:
            recommendations.append({
                "priority": "HIGH",
                "action": "Watch for phishing attempts and identity theft",
                "icon": "👤"
            })
        if combined_results["summary"]["breaches_detected"]:
            recommendations.append({
                "priority": "HIGH",
                "action": "Enable two-factor authentication on all accounts",
                "icon": "🔒"
            })
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Use unique passwords for each service",
                "icon": "🔑"
            })
        
        combined_results["recommendations"] = recommendations

        return combined_results


darkweb_service = DarkwebScannerService()
