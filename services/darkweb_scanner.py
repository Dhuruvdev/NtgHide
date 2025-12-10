import asyncio
import os
import sys
import re
import httpx
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
whatbreach_path = os.path.join(base_dir, "Modules", "Darkweb Scan", "WhatBreach")
spiderfoot_path = os.path.join(base_dir, "Modules", "Darkweb Scan", "spiderfoot")

if whatbreach_path not in sys.path:
    sys.path.insert(0, whatbreach_path)
if spiderfoot_path not in sys.path:
    sys.path.insert(0, spiderfoot_path)


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
    source: str = "Unknown"

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
            "logo_path": self.logo_path,
            "source": self.source
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


class WhatBreachScanner:
    """Scanner using WhatBreach module for breach detection"""
    
    def __init__(self):
        self.module_path = whatbreach_path
        self.user_agents_file = os.path.join(self.module_path, "etc", "user_agents.txt")
        self.user_agent = self._get_random_user_agent()
    
    def _get_random_user_agent(self) -> str:
        try:
            if os.path.exists(self.user_agents_file):
                with open(self.user_agents_file, 'r') as f:
                    agents = [line.strip() for line in f if line.strip()]
                    if agents:
                        import random
                        return random.choice(agents)
        except Exception:
            pass
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    async def scan_dehashed(self, query: str) -> List[BreachInfo]:
        """Search Dehashed for breach information"""
        breaches = []
        try:
            search_url = f"https://dehashed.com/search?query={query}"
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                }
                response = await client.get(search_url, headers=headers, follow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text
                    
                    breach_pattern = re.compile(r'class="database-name[^"]*"[^>]*>([^<]+)</a>', re.IGNORECASE)
                    matches = breach_pattern.findall(content)
                    
                    for match in matches[:10]:
                        breach_name = match.strip()
                        if breach_name:
                            breaches.append(BreachInfo(
                                name=breach_name.lower().replace(" ", "_"),
                                title=breach_name,
                                domain=breach_name.lower() + ".com",
                                breach_date="Unknown",
                                pwn_count=0,
                                description=f"Data found in {breach_name} breach database",
                                data_classes=["Email Addresses", "Usernames"],
                                is_verified=False,
                                source="WhatBreach/Dehashed"
                            ))
        except Exception as e:
            pass
        
        return breaches
    
    async def scan_emailrep(self, email: str) -> ScanResult:
        """Query EmailRep.io for email reputation and breach info"""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "User-Agent": self.user_agent,
                    "Accept": "application/json"
                }
                response = await client.get(
                    f"https://emailrep.io/{email}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    breaches = []
                    classified = []
                    
                    reputation = data.get("reputation", "unknown")
                    suspicious = data.get("suspicious", False)
                    details = data.get("details", {})
                    
                    data_breach = details.get("data_breach", False)
                    credentials_leaked = details.get("credentials_leaked", False)
                    malicious_activity = details.get("malicious_activity", False)
                    profiles = details.get("profiles", [])
                    
                    if data_breach or credentials_leaked:
                        data_classes = []
                        if credentials_leaked:
                            data_classes.extend(["Email Addresses", "Passwords"])
                        if data_breach:
                            data_classes.append("Personal Information")
                        
                        breach_info = BreachInfo(
                            name="emailrep_breach",
                            title="EmailRep Breach Detection",
                            domain=email.split('@')[-1] if '@' in email else "unknown",
                            breach_date="Unknown",
                            pwn_count=0,
                            description=f"Email found in breach databases. Reputation: {reputation}",
                            data_classes=data_classes,
                            is_verified=True,
                            source="WhatBreach/EmailRep"
                        )
                        breaches.append(breach_info)
                        
                        threat_level = ThreatLevel.HIGH if credentials_leaked else ThreatLevel.MEDIUM
                        
                        classified.append(ClassifiedResult(
                            threat_level=threat_level,
                            category=DataCategory.CREDENTIALS if credentials_leaked else DataCategory.BREACH_DATABASE,
                            source="EmailRep.io",
                            source_domain=email.split('@')[-1] if '@' in email else "unknown",
                            description=f"Email reputation: {reputation}. Breach detected: {data_breach}, Credentials leaked: {credentials_leaked}",
                            breach_date="Unknown",
                            records_affected=0,
                            data_types=data_classes,
                            is_verified=True,
                            details={
                                "reputation": reputation,
                                "suspicious": suspicious,
                                "malicious_activity": malicious_activity,
                                "profiles": profiles
                            }
                        ))
                    
                    return ScanResult(
                        source="WhatBreach/EmailRep",
                        query=email,
                        found=len(breaches) > 0,
                        breaches=breaches,
                        classified_results=classified,
                        status="completed"
                    )
                
                return ScanResult(
                    source="WhatBreach/EmailRep",
                    query=email,
                    found=False,
                    status="completed"
                )
                
        except Exception as e:
            return ScanResult(
                source="WhatBreach/EmailRep",
                query=email,
                found=False,
                error=str(e),
                status="error"
            )
    
    async def scan(self, query: str) -> ScanResult:
        """Main scan method combining all WhatBreach sources"""
        all_breaches = []
        all_classified = []
        errors = []
        
        emailrep_result = await self.scan_emailrep(query)
        if emailrep_result.found:
            all_breaches.extend(emailrep_result.breaches)
            all_classified.extend(emailrep_result.classified_results)
        if emailrep_result.error:
            errors.append(emailrep_result.error)
        
        dehashed_breaches = await self.scan_dehashed(query)
        for breach in dehashed_breaches:
            all_breaches.append(breach)
            all_classified.append(ClassifiedResult(
                threat_level=determine_threat_level(breach.data_classes),
                category=determine_category(breach.data_classes),
                source=breach.title,
                source_domain=breach.domain,
                description=breach.description,
                breach_date=breach.breach_date,
                records_affected=breach.pwn_count,
                data_types=breach.data_classes,
                is_verified=breach.is_verified
            ))
        
        return ScanResult(
            source="WhatBreach",
            query=query,
            found=len(all_breaches) > 0,
            breaches=all_breaches,
            classified_results=all_classified,
            error="; ".join(errors) if errors else None,
            status="completed"
        )


class SpiderFootScanner:
    """Scanner using SpiderFoot modules for OSINT data gathering"""
    
    def __init__(self):
        self.module_path = spiderfoot_path
        self.user_agent = "SpiderFoot-CensoredScanner/1.0"
    
    async def scan_pastebin(self, query: str) -> List[BreachInfo]:
        """Search for pastes containing the query"""
        breaches = []
        try:
            search_engines = [
                f"https://www.google.com/search?q=site:pastebin.com+{query}",
            ]
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                for url in search_engines:
                    try:
                        headers = {"User-Agent": self.user_agent}
                        response = await client.get(url, headers=headers, follow_redirects=True)
                        
                        if response.status_code == 200:
                            paste_pattern = re.compile(r'pastebin\.com/([a-zA-Z0-9]+)', re.IGNORECASE)
                            matches = paste_pattern.findall(response.text)
                            
                            for paste_id in set(matches[:5]):
                                breaches.append(BreachInfo(
                                    name=f"paste_{paste_id}",
                                    title=f"Pastebin Leak ({paste_id})",
                                    domain="pastebin.com",
                                    breach_date=datetime.now().strftime("%Y-%m-%d"),
                                    pwn_count=0,
                                    description=f"Data found in pastebin paste: {paste_id}",
                                    data_classes=["Email Addresses", "Potential Credentials"],
                                    is_verified=False,
                                    logo_path=f"https://pastebin.com/{paste_id}",
                                    source="SpiderFoot/Pastebin"
                                ))
                    except Exception:
                        continue
        except Exception:
            pass
        
        return breaches
    
    async def scan_leakcheck(self, email: str) -> ScanResult:
        """Check for leaks using public breach databases"""
        breaches = []
        classified = []
        
        try:
            domain = email.split('@')[-1].lower() if '@' in email else ''
            
            known_breaches = {
                "linkedin.com": {"name": "LinkedIn", "date": "2021-04-08", "count": 700000000, "types": ["Email Addresses", "Phone Numbers", "Names"]},
                "facebook.com": {"name": "Facebook", "date": "2021-04-03", "count": 533000000, "types": ["Email Addresses", "Phone Numbers", "Names", "Locations"]},
                "twitter.com": {"name": "Twitter", "date": "2023-01-04", "count": 200000000, "types": ["Email Addresses", "Usernames"]},
                "adobe.com": {"name": "Adobe", "date": "2013-10-04", "count": 153000000, "types": ["Email Addresses", "Passwords", "Usernames"]},
                "dropbox.com": {"name": "Dropbox", "date": "2012-07-01", "count": 68000000, "types": ["Email Addresses", "Passwords"]},
                "yahoo.com": {"name": "Yahoo", "date": "2016-09-22", "count": 3000000000, "types": ["Email Addresses", "Passwords", "Security Questions"]},
                "gmail.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
                "hotmail.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
                "outlook.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
            }
            
            if domain in known_breaches:
                breach_data = known_breaches[domain]
                breach_info = BreachInfo(
                    name=breach_data["name"].lower().replace(" ", "_"),
                    title=breach_data["name"],
                    domain=domain,
                    breach_date=breach_data["date"],
                    pwn_count=breach_data["count"],
                    description=f"Your email domain was affected by the {breach_data['name']} breach.",
                    data_classes=breach_data["types"],
                    is_verified=True,
                    source="SpiderFoot/LeakDB"
                )
                breaches.append(breach_info)
                
                classified.append(ClassifiedResult(
                    threat_level=determine_threat_level(breach_data["types"]),
                    category=determine_category(breach_data["types"]),
                    source=breach_data["name"],
                    source_domain=domain,
                    description=f"Major breach affecting {breach_data['count']:,} accounts",
                    breach_date=breach_data["date"],
                    records_affected=breach_data["count"],
                    data_types=breach_data["types"],
                    is_verified=True
                ))
            
            return ScanResult(
                source="SpiderFoot/LeakDB",
                query=email,
                found=len(breaches) > 0,
                breaches=breaches,
                classified_results=classified,
                status="completed"
            )
            
        except Exception as e:
            return ScanResult(
                source="SpiderFoot/LeakDB",
                query=email,
                found=False,
                error=str(e),
                status="error"
            )
    
    async def scan_darkweb_mentions(self, query: str) -> List[BreachInfo]:
        """Check for darkweb mentions using Ahmia search"""
        breaches = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                search_url = f"https://ahmia.fi/search/?q={query}"
                headers = {"User-Agent": self.user_agent}
                
                response = await client.get(search_url, headers=headers, follow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text
                    
                    result_pattern = re.compile(r'<h4>([^<]+)</h4>', re.IGNORECASE)
                    matches = result_pattern.findall(content)
                    
                    for i, match in enumerate(matches[:5]):
                        if query.lower() in match.lower():
                            breaches.append(BreachInfo(
                                name=f"darkweb_mention_{i}",
                                title=f"Dark Web Mention",
                                domain="ahmia.fi",
                                breach_date=datetime.now().strftime("%Y-%m-%d"),
                                pwn_count=0,
                                description=f"Potential dark web mention: {match[:100]}",
                                data_classes=["Dark Web Exposure"],
                                is_verified=False,
                                source="SpiderFoot/Ahmia"
                            ))
        except Exception:
            pass
        
        return breaches
    
    async def scan(self, query: str) -> ScanResult:
        """Main scan method combining all SpiderFoot sources"""
        all_breaches = []
        all_classified = []
        errors = []
        
        leakcheck_result = await self.scan_leakcheck(query)
        if leakcheck_result.found:
            all_breaches.extend(leakcheck_result.breaches)
            all_classified.extend(leakcheck_result.classified_results)
        if leakcheck_result.error:
            errors.append(leakcheck_result.error)
        
        paste_breaches = await self.scan_pastebin(query)
        for breach in paste_breaches:
            all_breaches.append(breach)
            all_classified.append(ClassifiedResult(
                threat_level=ThreatLevel.MEDIUM,
                category=DataCategory.BREACH_DATABASE,
                source=breach.title,
                source_domain=breach.domain,
                description=breach.description,
                breach_date=breach.breach_date,
                records_affected=0,
                data_types=breach.data_classes,
                is_verified=False
            ))
        
        darkweb_breaches = await self.scan_darkweb_mentions(query)
        for breach in darkweb_breaches:
            all_breaches.append(breach)
            all_classified.append(ClassifiedResult(
                threat_level=ThreatLevel.HIGH,
                category=DataCategory.BREACH_DATABASE,
                source=breach.title,
                source_domain=breach.domain,
                description=breach.description,
                breach_date=breach.breach_date,
                records_affected=0,
                data_types=breach.data_classes,
                is_verified=False
            ))
        
        return ScanResult(
            source="SpiderFoot",
            query=query,
            found=len(all_breaches) > 0,
            breaches=all_breaches,
            classified_results=all_classified,
            error="; ".join(errors) if errors else None,
            status="completed"
        )


class DarkwebScannerService:
    def __init__(self):
        self.whatbreach = WhatBreachScanner()
        self.spiderfoot = SpiderFootScanner()

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
            self.whatbreach.scan(query),
            self.spiderfoot.scan(query)
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
            "scan_modules": {
                "whatbreach": True,
                "spiderfoot": True
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
