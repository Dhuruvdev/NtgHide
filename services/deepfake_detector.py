import asyncio
import os
import base64
import tempfile
import re
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class DeepfakeResult:
    filename: str
    is_deepfake: Optional[bool]
    confidence: Optional[float]
    analysis_details: Dict[str, Any]
    error: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "filename": self.filename,
            "is_deepfake": self.is_deepfake,
            "confidence": self.confidence,
            "analysis_details": self.analysis_details,
            "error": self.error,
            "timestamp": self.timestamp
        }


class FACTORDetector:
    def __init__(self):
        self.module_path = "Modules/deepfake scan/FACTOR"

    async def analyze(self, file_path: str, filename: str) -> DeepfakeResult:
        try:
            if os.path.exists(self.module_path) and os.listdir(self.module_path):
                process = await asyncio.create_subprocess_exec(
                    "python", "detect.py", "--input", file_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=self.module_path
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
                
                if stdout:
                    output = stdout.decode()
                    is_fake = "fake" in output.lower() or "deepfake" in output.lower()
                    confidence = 0.0
                    
                    if "confidence" in output.lower():
                        try:
                            match = re.search(r'(\d+\.?\d*)%?', output)
                            if match:
                                confidence = float(match.group(1))
                                if confidence > 1:
                                    confidence = confidence / 100
                        except Exception:
                            pass
                    
                    return DeepfakeResult(
                        filename=filename,
                        is_deepfake=is_fake,
                        confidence=confidence,
                        analysis_details={"raw_output": output}
                    )
                    
                return DeepfakeResult(
                    filename=filename,
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error="No output from FACTOR module"
                )
            else:
                return DeepfakeResult(
                    filename=filename,
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error="FACTOR module not installed - add FACTOR to Modules/deepfake scan/FACTOR"
                )

        except asyncio.TimeoutError:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="Analysis timed out"
            )
        except Exception as e:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error=str(e)
            )


class DeepfakeDetectorService:
    def __init__(self):
        self.factor = FACTORDetector()

    async def analyze_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        try:
            result = await self.factor.analyze(tmp_path, filename)
            
            return {
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "result": result.to_dict(),
                "status": "completed" if result.error is None else "error"
            }
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    async def analyze_base64(self, base64_data: str, filename: str) -> Dict[str, Any]:
        try:
            if "," in base64_data:
                base64_data = base64_data.split(",")[1]
            
            file_content = base64.b64decode(base64_data)
            return await self.analyze_file(file_content, filename)
        except Exception as e:
            return {
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "result": DeepfakeResult(
                    filename=filename,
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error=f"Failed to decode file: {str(e)}"
                ).to_dict(),
                "status": "error"
            }


deepfake_service = DeepfakeDetectorService()
