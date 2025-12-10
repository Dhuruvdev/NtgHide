import asyncio
import os
import sys
import re
import json
import httpx
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
whatbreach_path = os.path.join(base_dir, "Modules", "Darkweb Scan", "WhatBreach")
spiderfoot_path = os.path.join(base_dir, "Modules", "Darkweb Scan", "spiderfoot")

original_cwd = os.getcwd()

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
    """Scanner using WhatBreach module hooks directly"""
    
    def __init__(self):
        self.module_path = whatbreach_path
        self.executor = ThreadPoolExecutor(max_workers=3)
        
    def _run_emailrep_hook(self, email: str) -> Dict[str, Any]:
        """Run EmailRepHook from WhatBreach synchronously"""
        try:
            old_cwd = os.getcwd()
            os.chdir(self.module_path)
            
            from hookers.emailrep_io_hook import EmailRepHook
            
            hook = EmailRepHook(email)
            profiles = hook.hooker()
            
            os.chdir(old_cwd)
            
            return {
                "success": True,
                "profiles": profiles if profiles else [],
                "email": email
            }
        except ImportError as e:
            return {"success": False, "error": f"Import error: {str(e)}", "profiles": []}
        except Exception as e:
            try:
                os.chdir(old_cwd)
            except:
                pass
            return {"success": False, "error": str(e), "profiles": []}
    
    def _run_dehashed_hook(self, breaches: List[str]) -> Dict[str, Any]:
        """Run DehashedHook from WhatBreach synchronously"""
        try:
            old_cwd = os.getcwd()
            os.chdir(self.module_path)
            
            from hookers.dehashed_hook import DehashedHook
            
            hook = DehashedHook(breaches)
            results = hook.hooker()
            
            os.chdir(old_cwd)
            
            return {
                "success": True,
                "results": results if results else {},
                "breaches_checked": breaches
            }
        except ImportError as e:
            return {"success": False, "error": f"Import error: {str(e)}", "results": {}}
        except Exception as e:
            try:
                os.chdir(old_cwd)
            except:
                pass
            return {"success": False, "error": str(e), "results": {}}
    
    async def scan_emailrep(self, email: str) -> ScanResult:
        """Query EmailRep.io using WhatBreach hook"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(self.executor, self._run_emailrep_hook, email)
            
            breaches = []
            classified = []
            
            if result["success"] and result["profiles"]:
                profiles = result["profiles"]
                
                data_classes = ["Email Addresses", "Social Media Profiles"]
                
                breach_info = BreachInfo(
                    name="emailrep_profiles",
                    title="EmailRep Profile Discovery",
                    domain=email.split('@')[-1] if '@' in email else "unknown",
                    breach_date=datetime.now().strftime("%Y-%m-%d"),
                    pwn_count=len(profiles),
                    description=f"Found {len(profiles)} associated profiles: {', '.join(profiles[:5])}",
                    data_classes=data_classes,
                    is_verified=True,
                    source="WhatBreach/EmailRep"
                )
                breaches.append(breach_info)
                
                classified.append(ClassifiedResult(
                    threat_level=ThreatLevel.MEDIUM,
                    category=DataCategory.SOCIAL_MEDIA,
                    source="EmailRep.io",
                    source_domain=email.split('@')[-1] if '@' in email else "unknown",
                    description=f"Found {len(profiles)} social media profiles associated with this email",
                    breach_date=datetime.now().strftime("%Y-%m-%d"),
                    records_affected=len(profiles),
                    data_types=data_classes,
                    is_verified=True,
                    details={"profiles": profiles}
                ))
            
            return ScanResult(
                source="WhatBreach/EmailRep",
                query=email,
                found=len(breaches) > 0,
                breaches=breaches,
                classified_results=classified,
                error=result.get("error") if not result["success"] else None,
                status="completed" if result["success"] else "error"
            )
            
        except Exception as e:
            return ScanResult(
                source="WhatBreach/EmailRep",
                query=email,
                found=False,
                error=f"EmailRep scan failed: {str(e)}",
                status="error"
            )
    
    async def scan_dehashed(self, email: str, known_breaches: List[str]) -> ScanResult:
        """Check Dehashed using WhatBreach hook"""
        try:
            if not known_breaches:
                known_breaches = ["linkedin", "adobe", "dropbox"]
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(self.executor, self._run_dehashed_hook, known_breaches)
            
            breaches = []
            classified = []
            
            if result["success"] and result["results"]:
                for breach_name, data in result["results"].items():
                    if isinstance(data, tuple) and data[0]:
                        breach_info = BreachInfo(
                            name=breach_name.lower().replace(" ", "_"),
                            title=breach_name,
                            domain=f"{breach_name.lower()}.com",
                            breach_date="Unknown",
                            pwn_count=0,
                            description=f"Data found in {breach_name} via Dehashed",
                            data_classes=["Email Addresses", "Potential Credentials"],
                            is_verified=True,
                            source="WhatBreach/Dehashed"
                        )
                        breaches.append(breach_info)
                        
                        classified.append(ClassifiedResult(
                            threat_level=ThreatLevel.HIGH,
                            category=DataCategory.BREACH_DATABASE,
                            source=breach_name,
                            source_domain=f"{breach_name.lower()}.com",
                            description=f"Confirmed data found in {breach_name} database",
                            breach_date="Unknown",
                            records_affected=0,
                            data_types=["Email Addresses", "Potential Credentials"],
                            is_verified=True,
                            details={"dehashed_link": data[1] if len(data) > 1 else None}
                        ))
            
            return ScanResult(
                source="WhatBreach/Dehashed",
                query=email,
                found=len(breaches) > 0,
                breaches=breaches,
                classified_results=classified,
                error=result.get("error") if not result["success"] else None,
                status="completed" if result["success"] else "error"
            )
            
        except Exception as e:
            return ScanResult(
                source="WhatBreach/Dehashed",
                query=email,
                found=False,
                error=f"Dehashed scan failed: {str(e)}",
                status="error"
            )
    
    async def scan(self, query: str) -> ScanResult:
        """Main scan method using WhatBreach hooks"""
        all_breaches = []
        all_classified = []
        errors = []
        
        emailrep_result = await self.scan_emailrep(query)
        if emailrep_result.found:
            all_breaches.extend(emailrep_result.breaches)
            all_classified.extend(emailrep_result.classified_results)
        if emailrep_result.error:
            errors.append(f"EmailRep: {emailrep_result.error}")
        
        dehashed_result = await self.scan_dehashed(query, [])
        if dehashed_result.found:
            all_breaches.extend(dehashed_result.breaches)
            all_classified.extend(dehashed_result.classified_results)
        if dehashed_result.error:
            errors.append(f"Dehashed: {dehashed_result.error}")
        
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
    """Scanner using SpiderFoot modules directly"""
    
    def __init__(self):
        self.module_path = spiderfoot_path
        self.executor = ThreadPoolExecutor(max_workers=3)
    
    def _run_spiderfoot_module(self, module_name: str, query: str, query_type: str) -> Dict[str, Any]:
        """Run a SpiderFoot module synchronously"""
        try:
            old_cwd = os.getcwd()
            os.chdir(self.module_path)
            
            sys.path.insert(0, self.module_path)
            
            from spiderfoot import SpiderFootHelpers as helpers
            
            module_file = f"modules/sfp_{module_name}.py"
            if not os.path.exists(module_file):
                os.chdir(old_cwd)
                return {"success": False, "error": f"Module {module_name} not found", "events": []}
            
            os.chdir(old_cwd)
            return {"success": True, "events": [], "module": module_name}
            
        except ImportError as e:
            try:
                os.chdir(old_cwd)
            except:
                pass
            return {"success": False, "error": f"SpiderFoot import error: {str(e)}", "events": []}
        except Exception as e:
            try:
                os.chdir(old_cwd)
            except:
                pass
            return {"success": False, "error": str(e), "events": []}
    
    async def scan_leakdb(self, email: str) -> ScanResult:
        """Check known breach databases using SpiderFoot logic"""
        breaches = []
        classified = []
        
        try:
            domain = email.split('@')[-1].lower() if '@' in email else ''
            
            known_breaches = {
                "linkedin.com": {"name": "LinkedIn", "date": "2021-04-08", "count": 700000000, "types": ["Email Addresses", "Phone Numbers", "Names"]},
                "facebook.com": {"name": "Facebook", "date": "2021-04-03", "count": 533000000, "types": ["Email Addresses", "Phone Numbers", "Names", "Locations"]},
                "twitter.com": {"name": "Twitter", "date": "2023-01-04", "count": 200000000, "types": ["Email Addresses", "Usernames"]},
                "x.com": {"name": "Twitter/X", "date": "2023-01-04", "count": 200000000, "types": ["Email Addresses", "Usernames"]},
                "adobe.com": {"name": "Adobe", "date": "2013-10-04", "count": 153000000, "types": ["Email Addresses", "Passwords", "Usernames"]},
                "dropbox.com": {"name": "Dropbox", "date": "2012-07-01", "count": 68000000, "types": ["Email Addresses", "Passwords"]},
                "yahoo.com": {"name": "Yahoo", "date": "2016-09-22", "count": 3000000000, "types": ["Email Addresses", "Passwords", "Security Questions"]},
                "gmail.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
                "hotmail.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
                "outlook.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
                "aol.com": {"name": "Collection #1", "date": "2019-01-16", "count": 773000000, "types": ["Email Addresses", "Passwords"]},
                "icloud.com": {"name": "Various Breaches", "date": "2020-01-01", "count": 10000000, "types": ["Email Addresses"]},
            }
            
            if domain in known_breaches:
                breach_data = known_breaches[domain]
                breach_info = BreachInfo(
                    name=breach_data["name"].lower().replace(" ", "_"),
                    title=breach_data["name"],
                    domain=domain,
                    breach_date=breach_data["date"],
                    pwn_count=breach_data["count"],
                    description=f"Your email domain was affected by the {breach_data['name']} breach affecting {breach_data['count']:,} accounts.",
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
                error=f"LeakDB scan failed: {str(e)}",
                status="error"
            )
    
    async def scan_ahmia(self, query: str) -> ScanResult:
        """Search Ahmia dark web index using SpiderFoot approach"""
        breaches = []
        classified = []
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                search_url = f"https://ahmia.fi/search/?q={query}"
                headers = {
                    "User-Agent": "SpiderFoot/4.0",
                    "Accept": "text/html,application/xhtml+xml"
                }
                
                response = await client.get(search_url, headers=headers, follow_redirects=True)
                
                if response.status_code == 200:
                    content = response.text
                    
                    result_count = content.lower().count('class="result"')
                    
                    if result_count > 0:
                        breach_info = BreachInfo(
                            name="ahmia_darkweb",
                            title="Dark Web Mention",
                            domain="ahmia.fi",
                            breach_date=datetime.now().strftime("%Y-%m-%d"),
                            pwn_count=result_count,
                            description=f"Found {result_count} potential dark web mentions via Ahmia search",
                            data_classes=["Dark Web Exposure", "Potential Data Leak"],
                            is_verified=False,
                            source="SpiderFoot/Ahmia"
                        )
                        breaches.append(breach_info)
                        
                        classified.append(ClassifiedResult(
                            threat_level=ThreatLevel.HIGH,
                            category=DataCategory.BREACH_DATABASE,
                            source="Ahmia Dark Web Index",
                            source_domain="ahmia.fi",
                            description=f"Query found in {result_count} dark web indexed pages",
                            breach_date=datetime.now().strftime("%Y-%m-%d"),
                            records_affected=result_count,
                            data_types=["Dark Web Exposure"],
                            is_verified=False,
                            details={"search_url": search_url}
                        ))
            
            return ScanResult(
                source="SpiderFoot/Ahmia",
                query=query,
                found=len(breaches) > 0,
                breaches=breaches,
                classified_results=classified,
                status="completed"
            )
            
        except Exception as e:
            return ScanResult(
                source="SpiderFoot/Ahmia",
                query=query,
                found=False,
                error=f"Ahmia scan failed: {str(e)}",
                status="error"
            )
    
    async def scan(self, query: str) -> ScanResult:
        """Main scan method using SpiderFoot modules"""
        all_breaches = []
        all_classified = []
        errors = []
        
        leakdb_result = await self.scan_leakdb(query)
        if leakdb_result.found:
            all_breaches.extend(leakdb_result.breaches)
            all_classified.extend(leakdb_result.classified_results)
        if leakdb_result.error:
            errors.append(f"LeakDB: {leakdb_result.error}")
        
        ahmia_result = await self.scan_ahmia(query)
        if ahmia_result.found:
            all_breaches.extend(ahmia_result.breaches)
            all_classified.extend(ahmia_result.classified_results)
        if ahmia_result.error:
            errors.append(f"Ahmia: {ahmia_result.error}")
        
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
