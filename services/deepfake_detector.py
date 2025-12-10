import asyncio
import os
import base64
import tempfile
import httpx
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

HUGGINGFACE_API_KEY = os.environ.get("HUGGINGFACE_API_KEY", "")

DEEPFAKE_MODEL = "microsoft/resnet-50"
DEEPFAKE_CLASSIFIER_MODEL = "umm-maybe/AI-image-detector"

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


class HuggingFaceDeepfakeDetector:
    def __init__(self):
        self.api_url = "https://api-inference.huggingface.co/models/"
        self.models = [
            "umm-maybe/AI-image-detector",
            "microsoft/resnet-50"
        ]
    
    async def analyze(self, file_content: bytes, filename: str) -> DeepfakeResult:
        if not HUGGINGFACE_API_KEY:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="Hugging Face API key not configured. Please set HUGGINGFACE_API_KEY."
            )
        
        try:
            headers = {
                "Authorization": f"Bearer {HUGGINGFACE_API_KEY}",
            }
            
            model_url = f"{self.api_url}umm-maybe/AI-image-detector"
            
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    model_url,
                    headers=headers,
                    content=file_content
                )
                
                if response.status_code == 200:
                    results = response.json()
                    
                    is_ai = False
                    ai_confidence = 0.0
                    human_confidence = 0.0
                    
                    if isinstance(results, list):
                        for item in results:
                            label = item.get("label", "").lower()
                            score = item.get("score", 0)
                            
                            if "artificial" in label or "ai" in label or "fake" in label or "generated" in label:
                                ai_confidence = max(ai_confidence, score)
                            elif "human" in label or "real" in label or "natural" in label:
                                human_confidence = max(human_confidence, score)
                        
                        is_ai = ai_confidence > human_confidence
                        confidence = ai_confidence if is_ai else human_confidence
                    
                    return DeepfakeResult(
                        filename=filename,
                        is_deepfake=is_ai,
                        confidence=confidence,
                        analysis_details={
                            "model": "umm-maybe/AI-image-detector",
                            "raw_results": results,
                            "ai_confidence": ai_confidence,
                            "human_confidence": human_confidence,
                            "verdict": "AI Generated" if is_ai else "Likely Authentic"
                        }
                    )
                elif response.status_code == 503:
                    return DeepfakeResult(
                        filename=filename,
                        is_deepfake=None,
                        confidence=None,
                        analysis_details={"status": "model_loading"},
                        error="Model is loading. Please try again in a few seconds."
                    )
                else:
                    return DeepfakeResult(
                        filename=filename,
                        is_deepfake=None,
                        confidence=None,
                        analysis_details={"status_code": response.status_code},
                        error=f"API error: {response.text[:200]}"
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


class FACTORDetector:
    def __init__(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.module_path = os.path.join(base_dir, "Modules", "deepfake scan", "FACTOR")
        self.detect_script = os.path.join(self.module_path, "detect.py")

    async def analyze(self, file_path: str, filename: str) -> DeepfakeResult:
        if not os.path.exists(self.detect_script):
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="FACTOR module not available"
            )
        
        try:
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
                
                import re
                confidence = 0.0
                confidence_match = re.search(r'Confidence:\s*(\d+\.?\d*)%', output)
                if confidence_match:
                    confidence = float(confidence_match.group(1)) / 100
                
                return DeepfakeResult(
                    filename=filename,
                    is_deepfake=is_fake,
                    confidence=confidence,
                    analysis_details={
                        "raw_output": output,
                        "result_status": "potential_deepfake" if is_fake else ("likely_authentic" if is_authentic else "inconclusive"),
                        "analysis_method": "FACTOR heuristic analysis"
                    }
                )
            
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="No output from FACTOR module"
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
        self.huggingface = HuggingFaceDeepfakeDetector()
        self.factor = FACTORDetector()

    async def analyze_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        hf_result = await self.huggingface.analyze(file_content, filename)
        
        return {
            "filename": filename,
            "timestamp": datetime.now().isoformat(),
            "result": hf_result.to_dict(),
            "status": "completed" if hf_result.error is None else "error",
            "detection_method": "Hugging Face AI Image Detector"
        }

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
