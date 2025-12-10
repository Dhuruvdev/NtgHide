import asyncio
import os
import subprocess
import json
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ScanResult:
    source: str
    query: str
    found: bool
    data: List[Dict[str, Any]]
    error: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "source": self.source,
            "query": self.query,
            "found": self.found,
            "data": self.data,
            "error": self.error,
            "timestamp": self.timestamp
        }


class H8MailScanner:
    def __init__(self):
        self.module_path = "Modules/Darkweb Scan/h8mail"

    async def scan(self, email: str) -> ScanResult:
        try:
            results = []
            found = False
            
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
                    results.append({"raw_output": output})
            else:
                return ScanResult(
                    source="h8mail",
                    query=email,
                    found=False,
                    data=[],
                    error="Module not installed - add h8mail to Modules/Darkweb Scan/h8mail"
                )

            return ScanResult(
                source="h8mail",
                query=email,
                found=found,
                data=results
            )
        except asyncio.TimeoutError:
            return ScanResult(
                source="h8mail",
                query=email,
                found=False,
                data=[],
                error="Scan timed out"
            )
        except Exception as e:
            return ScanResult(
                source="h8mail",
                query=email,
                found=False,
                data=[],
                error=str(e)
            )


class TorCrawlScanner:
    def __init__(self):
        self.module_path = "Modules/Darkweb Scan/TorCrawl.py"

    async def scan(self, query: str) -> ScanResult:
        try:
            results = []
            found = False

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
                    results.append({"raw_output": output, "search_url": f"https://ahmia.fi/search/?q={query}"})
            else:
                return ScanResult(
                    source="TorCrawl",
                    query=query,
                    found=False,
                    data=[],
                    error="Module not installed - add TorCrawl to Modules/Darkweb Scan/TorCrawl.py"
                )

            return ScanResult(
                source="TorCrawl",
                query=query,
                found=found,
                data=results
            )
        except asyncio.TimeoutError:
            return ScanResult(
                source="TorCrawl",
                query=query,
                found=False,
                data=[],
                error="Scan timed out"
            )
        except Exception as e:
            return ScanResult(
                source="TorCrawl",
                query=query,
                found=False,
                data=[],
                error=str(e)
            )


class WhatBreachScanner:
    def __init__(self):
        self.module_path = "Modules/Darkweb Scan/WhatBreach"

    async def scan(self, email: str) -> ScanResult:
        try:
            results = []
            found = False

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
                        results.append({"raw_output": output})
            else:
                return ScanResult(
                    source="WhatBreach",
                    query=email,
                    found=False,
                    data=[],
                    error="Module not installed - add WhatBreach to Modules/Darkweb Scan/WhatBreach"
                )

            return ScanResult(
                source="WhatBreach",
                query=email,
                found=found,
                data=results
            )
        except asyncio.TimeoutError:
            return ScanResult(
                source="WhatBreach",
                query=email,
                found=False,
                data=[],
                error="Scan timed out"
            )
        except Exception as e:
            return ScanResult(
                source="WhatBreach",
                query=email,
                found=False,
                data=[],
                error=str(e)
            )


class DarkwebScannerService:
    def __init__(self):
        self.h8mail = H8MailScanner()
        self.torcrawl = TorCrawlScanner()
        self.whatbreach = WhatBreachScanner()

    async def scan_all(self, query: str) -> Dict[str, Any]:
        tasks = [
            self.h8mail.scan(query),
            self.torcrawl.scan(query),
            self.whatbreach.scan(query)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        combined_results: Dict[str, Any] = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "sources": [],
            "total_found": 0,
            "summary": {
                "breaches_detected": False,
                "darkweb_mentions": False,
                "data_exposed": False
            }
        }
        
        for result in results:
            if isinstance(result, BaseException):
                combined_results["sources"].append({
                    "source": "Unknown",
                    "error": str(result),
                    "found": False,
                    "data": []
                })
            elif isinstance(result, ScanResult):
                combined_results["sources"].append(result.to_dict())
                if result.found:
                    combined_results["total_found"] += 1
                    if result.source in ["h8mail", "WhatBreach"]:
                        combined_results["summary"]["breaches_detected"] = True
                    if result.source == "TorCrawl":
                        combined_results["summary"]["darkweb_mentions"] = True
        
        if combined_results["total_found"] > 0:
            combined_results["summary"]["data_exposed"] = True
        
        return combined_results


darkweb_service = DarkwebScannerService()
