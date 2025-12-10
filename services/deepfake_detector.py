import asyncio
import os
import base64
import tempfile
import sys
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Modules", "deepfake scan", "MesoNet"))

MESONET_AVAILABLE = False
mesonet_detector = None

try:
    from mesonet_detector import MesoNetDetector
    mesonet_detector = MesoNetDetector()
    MESONET_AVAILABLE = True
except ImportError as e:
    print(f"MesoNet import error: {e}")
except Exception as e:
    print(f"MesoNet initialization error: {e}")


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


class MesoNetDeepfakeDetector:
    def __init__(self):
        self.detector = mesonet_detector
        self.available = MESONET_AVAILABLE
    
    async def analyze(self, file_content: bytes, filename: str) -> DeepfakeResult:
        if not self.available or self.detector is None:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="MesoNet detector not available"
            )
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self.detector.analyze_image, file_content
            )
            
            if not result.get("success", False):
                return DeepfakeResult(
                    filename=filename,
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error=result.get("error", "Analysis failed")
                )
            
            return DeepfakeResult(
                filename=filename,
                is_deepfake=result.get("is_deepfake", False),
                confidence=result.get("confidence", 0) / 100.0,
                analysis_details={
                    "verdict": result.get("verdict", "Unknown"),
                    "risk_level": result.get("risk_level", "Unknown"),
                    "analysis_method": result.get("analysis_method", "MesoNet Analysis"),
                    "component_scores": result.get("component_scores", {}),
                    "image_info": result.get("image_info", {})
                }
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
        self.mesonet = MesoNetDeepfakeDetector()

    async def analyze_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        result = await self.mesonet.analyze(file_content, filename)
        
        return {
            "filename": filename,
            "timestamp": datetime.now().isoformat(),
            "result": result.to_dict(),
            "status": "completed" if result.error is None else "error",
            "detection_method": "MesoNet Deepfake Detection",
            "model_available": self.mesonet.available
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
