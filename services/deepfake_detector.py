import asyncio
import os
import base64
import tempfile
import sys
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Modules", "deepfake scan", "MesoNet"))

MESONET_AVAILABLE = False
mesonet_detector = None
FACTOR_AVAILABLE = False

try:
    from mesonet_detector import MesoNetDetector
    mesonet_detector = MesoNetDetector()
    MESONET_AVAILABLE = True
except ImportError as e:
    print(f"MesoNet import error: {e}")
except Exception as e:
    print(f"MesoNet initialization error: {e}")

# Check if FACTOR is available
factor_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Modules", "deepfake scan", "FACTOR")
if os.path.exists(os.path.join(factor_path, "detect.py")):
    FACTOR_AVAILABLE = True
    print("FACTOR model available for advanced deepfake detection")


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


class FACTORDeepfakeDetector:
    def __init__(self):
        self.available = FACTOR_AVAILABLE
        self.factor_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Modules", "deepfake scan", "FACTOR")
    
    async def analyze(self, file_content: bytes, filename: str) -> DeepfakeResult:
        if not self.available:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="FACTOR detector not available"
            )
        
        try:
            # Save file to temporary location
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp_file:
                tmp_file.write(file_content)
                tmp_path = tmp_file.name
            
            try:
                # Run FACTOR detection
                result = await asyncio.get_event_loop().run_in_executor(
                    None, self._run_factor_detect, tmp_path
                )
                return result
            finally:
                # Clean up temp file
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                    
        except Exception as e:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error=str(e)
            )
    
    def _run_factor_detect(self, file_path: str) -> DeepfakeResult:
        """Run FACTOR detection script"""
        try:
            # Run the FACTOR detect.py script
            result = subprocess.run(
                [sys.executable, os.path.join(self.factor_path, "detect.py"), file_path],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=self.factor_path
            )
            
            if result.returncode == 0:
                # Parse output - FACTOR returns confidence score
                output = result.stdout.strip()
                
                # Extract confidence from output (format depends on detect.py implementation)
                confidence = 0.0
                is_deepfake = False
                
                if "confidence" in output.lower():
                    # Try to extract confidence value
                    parts = output.split(":")
                    if len(parts) > 1:
                        try:
                            confidence = float(parts[-1].strip().rstrip('%')) / 100.0
                            is_deepfake = confidence > 0.5
                        except ValueError:
                            pass
                
                return DeepfakeResult(
                    filename=os.path.basename(file_path),
                    is_deepfake=is_deepfake,
                    confidence=confidence,
                    analysis_details={
                        "method": "FACTOR - Face Forgery Detection",
                        "output": output,
                        "description": "Zero-shot deepfake detection using FACTOR model"
                    }
                )
            else:
                return DeepfakeResult(
                    filename=os.path.basename(file_path),
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error=f"FACTOR detection failed: {result.stderr}"
                )
                
        except subprocess.TimeoutExpired:
            return DeepfakeResult(
                filename=os.path.basename(file_path),
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error="FACTOR detection timeout"
            )
        except Exception as e:
            return DeepfakeResult(
                filename=os.path.basename(file_path),
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error=f"FACTOR error: {str(e)}"
            )


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
        self.factor = FACTORDeepfakeDetector()
        self.mesonet = MesoNetDeepfakeDetector()

    async def analyze_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        # Try FACTOR first (more advanced), fallback to MesoNet
        if self.factor.available:
            result = await self.factor.analyze(file_content, filename)
            detection_method = "FACTOR Advanced Deepfake Detection"
            model_available = self.factor.available
            
            # If FACTOR fails, try MesoNet as backup
            if result.error and self.mesonet.available:
                result = await self.mesonet.analyze(file_content, filename)
                detection_method = "MesoNet Deepfake Detection (FACTOR fallback)"
                model_available = self.mesonet.available
        else:
            result = await self.mesonet.analyze(file_content, filename)
            detection_method = "MesoNet Deepfake Detection"
            model_available = self.mesonet.available
        
        return {
            "filename": filename,
            "timestamp": datetime.now().isoformat(),
            "result": result.to_dict(),
            "status": "completed" if result.error is None else "error",
            "detection_method": detection_method,
            "model_available": model_available,
            "factor_available": self.factor.available,
            "mesonet_available": self.mesonet.available
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
