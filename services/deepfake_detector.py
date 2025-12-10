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
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.module_path = os.path.join(base_dir, "Modules", "deepfake scan", "FACTOR")
        self.detect_script = os.path.join(self.module_path, "detect.py")

    async def analyze(self, file_path: str, filename: str) -> DeepfakeResult:
        try:
            if os.path.exists(self.detect_script):
                abs_file_path = os.path.abspath(file_path)
                
                process = await asyncio.create_subprocess_exec(
                    "python", self.detect_script, "--input", abs_file_path, "--verbose",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
                
                if stdout:
                    output = stdout.decode()
                    
                    is_fake = "POTENTIAL DEEPFAKE DETECTED" in output
                    is_authentic = "LIKELY AUTHENTIC" in output
                    
                    confidence = 0.0
                    confidence_match = re.search(r'Confidence:\s*(\d+\.?\d*)%', output)
                    if confidence_match:
                        confidence = float(confidence_match.group(1)) / 100
                    
                    if is_fake:
                        result_status = "potential_deepfake"
                    elif is_authentic:
                        result_status = "likely_authentic"
                    else:
                        result_status = "inconclusive"
                    
                    return DeepfakeResult(
                        filename=filename,
                        is_deepfake=is_fake,
                        confidence=confidence,
                        analysis_details={
                            "raw_output": output,
                            "result_status": result_status,
                            "analysis_method": "FACTOR heuristic analysis"
                        }
                    )
                
                if stderr:
                    error_output = stderr.decode()
                    return DeepfakeResult(
                        filename=filename,
                        is_deepfake=None,
                        confidence=None,
                        analysis_details={"stderr": error_output},
                        error=f"Analysis error: {error_output[:200]}"
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
                    error="FACTOR detect.py not found - module may not be properly installed"
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
