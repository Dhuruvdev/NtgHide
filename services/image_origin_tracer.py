import asyncio
import base64
import io
import os
import struct
import hashlib
import httpx
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import numpy as np
import cv2
from scipy import fftpack


@dataclass
class ImageOriginResult:
    filename: str
    file_hash: str
    exif_data: Dict[str, Any]
    exif_anomalies: List[Dict[str, Any]]
    manipulation_indicators: List[Dict[str, Any]]
    online_matches: List[Dict[str, Any]]
    risk_score: int
    verdict: str
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "filename": self.filename,
            "file_hash": self.file_hash,
            "exif_data": self.exif_data,
            "exif_anomalies": self.exif_anomalies,
            "manipulation_indicators": self.manipulation_indicators,
            "online_matches": self.online_matches,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "timestamp": self.timestamp
        }


class EXIFAnalyzer:
    """Extract and analyze EXIF metadata for anomalies"""
    
    CRITICAL_TAGS = [
        'Make', 'Model', 'Software', 'DateTime', 'DateTimeOriginal',
        'DateTimeDigitized', 'GPSInfo', 'ImageWidth', 'ImageLength',
        'ExifImageWidth', 'ExifImageHeight', 'Artist', 'Copyright',
        'XPAuthor', 'XPComment', 'HostComputer'
    ]
    
    EDITING_SOFTWARE = [
        'photoshop', 'gimp', 'lightroom', 'illustrator', 'paint',
        'snapseed', 'pixlr', 'canva', 'faceapp', 'facetune',
        'airbrush', 'beautycam', 'meitu', 'vsco', 'afterlight',
        'picsart', 'remini', 'reface', 'deepfake', 'faceswap',
        'midjourney', 'dall-e', 'stable diffusion', 'ai generated'
    ]
    
    def extract_exif(self, image: Image.Image) -> Dict[str, Any]:
        """Extract all EXIF data from image"""
        exif_data = {}
        
        try:
            raw_exif = image._getexif()
            if raw_exif:
                for tag_id, value in raw_exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    
                    if tag == 'GPSInfo':
                        gps_data = {}
                        for gps_tag_id, gps_value in value.items():
                            gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            gps_data[gps_tag] = self._convert_value(gps_value)
                        exif_data['GPSInfo'] = gps_data
                    else:
                        exif_data[tag] = self._convert_value(value)
        except Exception:
            pass
        
        try:
            info = image.info
            for key, value in info.items():
                if key not in exif_data:
                    exif_data[f"info_{key}"] = self._convert_value(value)
        except Exception:
            pass
        
        return exif_data
    
    def _convert_value(self, value) -> Any:
        """Convert EXIF values to JSON-serializable format"""
        if isinstance(value, bytes):
            try:
                return value.decode('utf-8', errors='ignore')
            except:
                return f"<binary: {len(value)} bytes>"
        elif isinstance(value, tuple):
            return [self._convert_value(v) for v in value]
        elif hasattr(value, 'numerator'):
            return float(value)
        else:
            return str(value) if not isinstance(value, (int, float, str, list, dict, type(None))) else value
    
    def analyze_anomalies(self, exif_data: Dict[str, Any], image: Image.Image) -> List[Dict[str, Any]]:
        """Detect anomalies in EXIF data that suggest manipulation"""
        anomalies = []
        
        if not exif_data or len(exif_data) < 3:
            anomalies.append({
                "type": "MISSING_EXIF",
                "severity": "HIGH",
                "description": "Image has missing or stripped EXIF data - common in manipulated images",
                "detail": "Authentic camera photos typically contain extensive metadata"
            })
        
        software = exif_data.get('Software', '').lower()
        if software:
            for editor in self.EDITING_SOFTWARE:
                if editor in software:
                    anomalies.append({
                        "type": "EDITING_SOFTWARE",
                        "severity": "MEDIUM" if 'ai' not in editor and 'deepfake' not in editor else "CRITICAL",
                        "description": f"Image was processed with editing software: {exif_data.get('Software')}",
                        "detail": "This indicates the image has been modified from its original state"
                    })
                    break
        
        datetime_original = exif_data.get('DateTimeOriginal')
        datetime_digitized = exif_data.get('DateTimeDigitized')
        datetime_modified = exif_data.get('DateTime')
        
        if datetime_original and datetime_modified:
            try:
                orig = datetime.strptime(datetime_original, '%Y:%m:%d %H:%M:%S')
                mod = datetime.strptime(datetime_modified, '%Y:%m:%d %H:%M:%S')
                
                if mod < orig:
                    anomalies.append({
                        "type": "DATE_INCONSISTENCY",
                        "severity": "HIGH",
                        "description": "Modification date is earlier than original capture date",
                        "detail": f"Original: {datetime_original}, Modified: {datetime_modified}"
                    })
                elif (mod - orig).days > 365:
                    anomalies.append({
                        "type": "DATE_GAP",
                        "severity": "LOW",
                        "description": "Large gap between capture and modification dates",
                        "detail": f"Gap of {(mod - orig).days} days between dates"
                    })
            except:
                pass
        
        exif_width = exif_data.get('ExifImageWidth') or exif_data.get('ImageWidth')
        exif_height = exif_data.get('ExifImageHeight') or exif_data.get('ImageLength')
        actual_width, actual_height = image.size
        
        if exif_width and exif_height:
            try:
                if int(exif_width) != actual_width or int(exif_height) != actual_height:
                    anomalies.append({
                        "type": "DIMENSION_MISMATCH",
                        "severity": "HIGH",
                        "description": "Image dimensions don't match EXIF metadata",
                        "detail": f"EXIF: {exif_width}x{exif_height}, Actual: {actual_width}x{actual_height}"
                    })
            except:
                pass
        
        make = exif_data.get('Make', '')
        model = exif_data.get('Model', '')
        
        if make and model:
            make_lower = make.lower()
            model_lower = model.lower()
            
            known_inconsistencies = [
                ('apple', 'samsung'),
                ('canon', 'nikon'),
                ('samsung', 'apple'),
                ('huawei', 'iphone'),
            ]
            
            for m1, m2 in known_inconsistencies:
                if m1 in make_lower and m2 in model_lower:
                    anomalies.append({
                        "type": "CAMERA_INCONSISTENCY",
                        "severity": "HIGH",
                        "description": "Camera make and model are inconsistent",
                        "detail": f"Make: {make}, Model: {model}"
                    })
                    break
        
        if 'GPSInfo' in exif_data:
            gps = exif_data['GPSInfo']
            if isinstance(gps, dict):
                lat = gps.get('GPSLatitude')
                lon = gps.get('GPSLongitude')
                if lat and lon:
                    anomalies.append({
                        "type": "GPS_DATA_PRESENT",
                        "severity": "INFO",
                        "description": "Image contains GPS location data",
                        "detail": "Location data can help verify image authenticity"
                    })
        
        thumbnail = exif_data.get('info_thumbnail') or exif_data.get('ThumbnailImage')
        if thumbnail:
            anomalies.append({
                "type": "THUMBNAIL_PRESENT",
                "severity": "INFO",
                "description": "Image contains embedded thumbnail",
                "detail": "Thumbnails can be compared to detect manipulation"
            })
        
        return anomalies


class ManipulationHistoryAnalyzer:
    """Analyze image for signs of manipulation history"""
    
    def analyze(self, img_array: np.ndarray, pil_image: Image.Image) -> List[Dict[str, Any]]:
        """Detect manipulation indicators"""
        indicators = []
        
        quantization = self._analyze_jpeg_quantization(pil_image)
        if quantization:
            indicators.append(quantization)
        
        recompression = self._detect_recompression(img_array)
        if recompression:
            indicators.append(recompression)
        
        cloning = self._detect_clone_regions(img_array)
        if cloning:
            indicators.append(cloning)
        
        splicing = self._detect_splicing(img_array)
        if splicing:
            indicators.append(splicing)
        
        resize = self._detect_resize_artifacts(img_array)
        if resize:
            indicators.append(resize)
        
        return indicators
    
    def _analyze_jpeg_quantization(self, pil_image: Image.Image) -> Optional[Dict[str, Any]]:
        """Analyze JPEG quantization tables for manipulation signs"""
        try:
            if hasattr(pil_image, 'quantization'):
                qtables = pil_image.quantization
                if qtables:
                    values = []
                    for table in qtables.values():
                        values.extend(list(table))
                    
                    avg_q = np.mean(values)
                    
                    if avg_q > 50:
                        return {
                            "type": "HIGH_COMPRESSION",
                            "severity": "MEDIUM",
                            "description": "Image shows signs of high JPEG compression",
                            "detail": f"Average quantization value: {avg_q:.1f} (higher = more compression)",
                            "confidence": min(avg_q / 100, 1.0)
                        }
        except:
            pass
        return None
    
    def _detect_recompression(self, img_array: np.ndarray) -> Optional[Dict[str, Any]]:
        """Detect signs of multiple JPEG compressions"""
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        h, w = gray.shape
        block_size = 8
        boundary_diffs = []
        
        for i in range(block_size, h - block_size, block_size):
            for j in range(block_size, w - block_size, block_size):
                diff = abs(float(gray[i, j]) - float(gray[i-1, j]))
                boundary_diffs.append(diff)
        
        if boundary_diffs:
            avg_diff = np.mean(boundary_diffs)
            std_diff = np.std(boundary_diffs)
            
            if avg_diff > 8 and std_diff > 5:
                return {
                    "type": "RECOMPRESSION_DETECTED",
                    "severity": "MEDIUM",
                    "description": "Image shows signs of multiple JPEG compressions",
                    "detail": f"Block boundary artifacts detected (avg: {avg_diff:.2f})",
                    "confidence": min(avg_diff / 20, 1.0)
                }
        return None
    
    def _detect_clone_regions(self, img_array: np.ndarray) -> Optional[Dict[str, Any]]:
        """Detect copy-paste/clone regions using block matching"""
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        small = cv2.resize(gray, (256, 256))
        
        block_size = 16
        blocks = {}
        
        for i in range(0, 256 - block_size, 8):
            for j in range(0, 256 - block_size, 8):
                block = small[i:i+block_size, j:j+block_size]
                block_hash = hashlib.md5(block.tobytes()).hexdigest()[:8]
                
                if block_hash in blocks:
                    prev_i, prev_j = blocks[block_hash]
                    distance = np.sqrt((i - prev_i)**2 + (j - prev_j)**2)
                    
                    if distance > block_size * 2:
                        return {
                            "type": "CLONE_DETECTED",
                            "severity": "HIGH",
                            "description": "Possible copy-paste manipulation detected",
                            "detail": "Similar blocks found in different regions of the image",
                            "confidence": 0.7
                        }
                else:
                    blocks[block_hash] = (i, j)
        
        return None
    
    def _detect_splicing(self, img_array: np.ndarray) -> Optional[Dict[str, Any]]:
        """Detect splicing by analyzing noise levels across regions"""
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        h, w = gray.shape
        grid = 4
        noise_levels = []
        
        for i in range(grid):
            for j in range(grid):
                region = gray[i*h//grid:(i+1)*h//grid, j*w//grid:(j+1)*w//grid]
                laplacian = cv2.Laplacian(region, cv2.CV_64F)
                noise_levels.append(laplacian.var())
        
        if noise_levels:
            noise_std = np.std(noise_levels)
            noise_range = max(noise_levels) - min(noise_levels)
            
            if noise_range > 500 and noise_std > 100:
                return {
                    "type": "SPLICING_SUSPECTED",
                    "severity": "HIGH",
                    "description": "Inconsistent noise levels suggest image splicing",
                    "detail": f"Noise variance across regions: {noise_std:.1f}",
                    "confidence": min(noise_std / 200, 1.0)
                }
        
        return None
    
    def _detect_resize_artifacts(self, img_array: np.ndarray) -> Optional[Dict[str, Any]]:
        """Detect resize/scaling artifacts"""
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        gray_float = gray.astype(np.float64)
        
        f_transform = np.fft.fft2(gray_float)
        f_shift = np.fft.fftshift(f_transform)
        magnitude = np.abs(f_shift)
        
        h, w = magnitude.shape
        cy, cx = h // 2, w // 2
        
        for r in range(10, min(cx, cy), 5):
            ring = []
            for angle in range(0, 360, 5):
                rad = np.deg2rad(angle)
                x = int(cx + r * np.cos(rad))
                y = int(cy + r * np.sin(rad))
                if 0 <= x < w and 0 <= y < h:
                    ring.append(magnitude[y, x])
            
            if ring:
                ring_std = np.std(ring)
                ring_mean = np.mean(ring)
                
                if ring_std / (ring_mean + 1e-10) > 2:
                    return {
                        "type": "RESIZE_ARTIFACTS",
                        "severity": "LOW",
                        "description": "Image may have been resized or scaled",
                        "detail": "Frequency domain shows periodic patterns typical of resizing",
                        "confidence": 0.5
                    }
        
        return None


class ReverseImageSearch:
    """Search for image matches online using free APIs"""
    
    async def search(self, img_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
        """Search for the image online"""
        matches = []
        
        file_hash = hashlib.sha256(img_bytes).hexdigest()
        
        matches.append({
            "source": "SHA256 Hash",
            "hash": file_hash,
            "description": "Use this hash to search on blockchain verification services",
            "search_url": None
        })
        
        try:
            img_b64 = base64.b64encode(img_bytes).decode('utf-8')
            
            matches.append({
                "source": "Google Images",
                "description": "Search Google for visually similar images",
                "search_url": "https://images.google.com/ (upload image)",
                "method": "Manual upload required"
            })
            
            matches.append({
                "source": "TinEye",
                "description": "Reverse image search engine",
                "search_url": "https://tineye.com/ (upload image)",
                "method": "Manual upload required"
            })
            
            matches.append({
                "source": "Yandex Images",
                "description": "Often finds results Google misses",
                "search_url": "https://yandex.com/images/ (upload image)",
                "method": "Manual upload required"
            })
            
            matches.append({
                "source": "Bing Visual Search",
                "description": "Microsoft's reverse image search",
                "search_url": "https://www.bing.com/visualsearch (upload image)",
                "method": "Manual upload required"
            })
            
        except Exception as e:
            matches.append({
                "source": "Error",
                "description": f"Could not prepare image for search: {str(e)}",
                "search_url": None
            })
        
        return matches


class ImageOriginService:
    """Main service for image origin tracing"""
    
    def __init__(self):
        self.exif_analyzer = EXIFAnalyzer()
        self.manipulation_analyzer = ManipulationHistoryAnalyzer()
        self.reverse_search = ReverseImageSearch()
    
    async def analyze(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Comprehensive image origin analysis"""
        try:
            pil_image = Image.open(io.BytesIO(file_bytes))
            
            nparr = np.frombuffer(file_bytes, np.uint8)
            img_array = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img_array is None:
                img_array = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            
            loop = asyncio.get_event_loop()
            
            exif_task = loop.run_in_executor(None, self.exif_analyzer.extract_exif, pil_image)
            
            exif_data = await exif_task
            
            anomalies_task = loop.run_in_executor(
                None, self.exif_analyzer.analyze_anomalies, exif_data, pil_image
            )
            manipulation_task = loop.run_in_executor(
                None, self.manipulation_analyzer.analyze, img_array, pil_image
            )
            search_task = self.reverse_search.search(file_bytes, filename)
            
            anomalies, manipulation, online_matches = await asyncio.gather(
                anomalies_task, manipulation_task, search_task
            )
            
            risk_score = self._calculate_risk_score(anomalies, manipulation)
            verdict = self._get_verdict(risk_score, anomalies, manipulation)
            
            result = ImageOriginResult(
                filename=filename,
                file_hash=file_hash,
                exif_data=self._sanitize_exif(exif_data),
                exif_anomalies=anomalies,
                manipulation_indicators=manipulation,
                online_matches=online_matches,
                risk_score=risk_score,
                verdict=verdict
            )
            
            return result.to_dict()
            
        except Exception as e:
            return {
                "filename": filename,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _sanitize_exif(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize EXIF data for JSON serialization"""
        sanitized = {}
        for key, value in exif_data.items():
            try:
                import json
                json.dumps({key: value})
                sanitized[key] = value
            except:
                sanitized[key] = str(value)
        return sanitized
    
    def _calculate_risk_score(self, anomalies: List, manipulation: List) -> int:
        """Calculate overall risk score"""
        score = 0
        
        severity_weights = {
            "CRITICAL": 30,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
            "INFO": 0
        }
        
        for anomaly in anomalies:
            severity = anomaly.get("severity", "LOW")
            score += severity_weights.get(severity, 5)
        
        for indicator in manipulation:
            severity = indicator.get("severity", "LOW")
            confidence = indicator.get("confidence", 0.5)
            score += int(severity_weights.get(severity, 5) * confidence)
        
        return min(score, 100)
    
    def _get_verdict(self, risk_score: int, anomalies: List, manipulation: List) -> str:
        """Generate verdict based on analysis"""
        critical_count = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
        critical_count += sum(1 for m in manipulation if m.get("severity") == "CRITICAL")
        
        high_count = sum(1 for a in anomalies if a.get("severity") == "HIGH")
        high_count += sum(1 for m in manipulation if m.get("severity") == "HIGH")
        
        if critical_count > 0 or risk_score >= 60:
            return "HIGH RISK - Likely manipulated or fake"
        elif high_count >= 2 or risk_score >= 40:
            return "MEDIUM RISK - Signs of editing detected"
        elif risk_score >= 20:
            return "LOW RISK - Minor anomalies detected"
        else:
            return "MINIMAL RISK - Appears authentic"


image_origin_service = ImageOriginService()
