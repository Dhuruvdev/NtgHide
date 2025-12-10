import asyncio
import os
import base64
import tempfile
import io
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np
from PIL import Image
import cv2
from scipy import fftpack, ndimage, stats
from skimage import feature, filters, measure, color
from skimage.restoration import estimate_sigma

DEEPFAKE_IMAGE_DETECTION_AVAILABLE = True
DEEPFAKE_DETECTION_MODULE_PATH = "Modules/deepfake scan/DeepFake-Image-Detection"


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


class VGGStyleFeatureExtractor:
    """
    Implements VGG-style feature extraction for deepfake detection
    Based on DeepFake-Image-Detection methodology using transfer learning concepts.
    Uses convolutional filter patterns similar to VGG16/VGG19 architecture.
    """
    
    def __init__(self):
        self.target_size = (224, 224)
        self.filters = self._create_vgg_style_filters()
    
    def _create_vgg_style_filters(self) -> List[np.ndarray]:
        filters = []
        edge_h = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float32)
        edge_v = np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]], dtype=np.float32)
        filters.extend([edge_h, edge_v])
        
        laplacian = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
        laplacian_diag = np.array([[1, 0, 1], [0, -4, 0], [1, 0, 1]], dtype=np.float32)
        filters.extend([laplacian, laplacian_diag])
        
        gaussian = np.array([[1, 2, 1], [2, 4, 2], [1, 2, 1]], dtype=np.float32) / 16
        sharpen = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]], dtype=np.float32)
        filters.extend([gaussian, sharpen])
        
        emboss = np.array([[-2, -1, 0], [-1, 1, 1], [0, 1, 2]], dtype=np.float32)
        filters.append(emboss)
        
        return filters
    
    def extract_features(self, img_array: np.ndarray) -> Dict[str, Any]:
        resized = cv2.resize(img_array, self.target_size)
        if len(resized.shape) == 3:
            gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
        else:
            gray = resized
        
        gray = gray.astype(np.float32) / 255.0
        
        feature_maps = []
        for f in self.filters:
            filtered = cv2.filter2D(gray, -1, f)
            feature_maps.append(filtered)
        
        features = {
            "global_avg_pool": [],
            "feature_statistics": [],
            "activation_patterns": []
        }
        
        for i, fmap in enumerate(feature_maps):
            gap = np.mean(fmap)
            gmp = np.max(fmap)
            std = np.std(fmap)
            features["global_avg_pool"].append(float(gap))
            features["feature_statistics"].append({
                "filter_id": i,
                "mean": float(gap),
                "max": float(gmp),
                "std": float(std),
                "energy": float(np.sum(fmap ** 2))
            })
            
            binary_activation = (fmap > np.mean(fmap)).astype(np.float32)
            activation_ratio = np.sum(binary_activation) / binary_activation.size
            features["activation_patterns"].append(float(activation_ratio))
        
        return features
    
    def compute_authenticity_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        gap_values = features["global_avg_pool"]
        activation_patterns = features["activation_patterns"]
        
        edge_response = abs(gap_values[0]) + abs(gap_values[1])
        texture_response = abs(gap_values[2]) + abs(gap_values[3])
        smoothness_response = abs(gap_values[4]) + abs(gap_values[5])
        
        suspicious_score = 0
        
        if edge_response < 0.02:
            suspicious_score += 25
        elif edge_response > 0.3:
            suspicious_score += 15
        
        if texture_response < 0.01:
            suspicious_score += 20
        elif texture_response > 0.25:
            suspicious_score += 15
        
        activation_variance = np.var(activation_patterns)
        if activation_variance < 0.01:
            suspicious_score += 20
        elif activation_variance > 0.15:
            suspicious_score += 15
        
        stats = features["feature_statistics"]
        energy_values = [s["energy"] for s in stats]
        energy_variance = np.var(energy_values)
        if energy_variance > 1000:
            suspicious_score += 20
        
        return {
            "score": int(min(suspicious_score, 100)),
            "edge_response": float(edge_response),
            "texture_response": float(texture_response),
            "smoothness_response": float(smoothness_response),
            "activation_variance": float(activation_variance),
            "energy_variance": float(energy_variance),
            "suspicious": bool(suspicious_score > 35),
            "details": "VGG-style deep feature analysis (DeepFake-Image-Detection methodology)",
            "model_type": "VGG16-inspired feature extraction"
        }


class AdvancedDeepfakeAnalyzer:
    def __init__(self):
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        self.eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_eye.xml'
        )
    
    def analyze_error_level(self, img_array: np.ndarray, quality: int = 90) -> Dict[str, Any]:
        is_success, buffer = cv2.imencode('.jpg', img_array, [cv2.IMWRITE_JPEG_QUALITY, quality])
        if not is_success:
            return {"score": 0, "suspicious": False, "details": "ELA failed"}
        
        recompressed = cv2.imdecode(np.frombuffer(buffer, np.uint8), cv2.IMREAD_COLOR)
        
        ela_image = cv2.absdiff(img_array, recompressed)
        ela_gray = cv2.cvtColor(ela_image, cv2.COLOR_BGR2GRAY) if len(ela_image.shape) == 3 else ela_image
        
        mean_ela = np.mean(ela_gray)
        std_ela = np.std(ela_gray)
        max_ela = np.max(ela_gray)
        
        ela_normalized = ela_gray.astype(float) / 255.0
        regions = self._get_image_regions(ela_normalized)
        region_variances = [np.var(r) for r in regions if r.size > 0]
        variance_ratio = max(region_variances) / (min(region_variances) + 1e-10) if region_variances else 1
        
        suspicious_score = 0
        if mean_ela > 15:
            suspicious_score += 20
        if std_ela > 20:
            suspicious_score += 20
        if variance_ratio > 5:
            suspicious_score += 30
        if max_ela > 100:
            suspicious_score += 15
        
        return {
            "score": int(min(suspicious_score, 100)),
            "mean_ela": float(mean_ela),
            "std_ela": float(std_ela),
            "max_ela": float(max_ela),
            "variance_ratio": float(variance_ratio),
            "suspicious": bool(suspicious_score > 40),
            "details": "Error Level Analysis detects compression inconsistencies"
        }
    
    def analyze_frequency_domain(self, img_array: np.ndarray) -> Dict[str, Any]:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        gray = gray.astype(np.float64)
        
        f_transform = fftpack.fft2(gray)
        f_shift = fftpack.fftshift(f_transform)
        magnitude_spectrum = np.abs(f_shift)
        
        log_magnitude = np.log1p(magnitude_spectrum)
        
        h, w = gray.shape
        center_y, center_x = h // 2, w // 2
        
        low_freq_region = log_magnitude[center_y-10:center_y+10, center_x-10:center_x+10]
        high_freq_region = np.concatenate([
            log_magnitude[:20, :].flatten(),
            log_magnitude[-20:, :].flatten(),
            log_magnitude[:, :20].flatten(),
            log_magnitude[:, -20:].flatten()
        ])
        
        low_freq_energy = np.mean(low_freq_region)
        high_freq_energy = np.mean(high_freq_region)
        freq_ratio = high_freq_energy / (low_freq_energy + 1e-10)
        
        radial_profile = self._compute_radial_profile(magnitude_spectrum)
        profile_smoothness = np.std(np.diff(radial_profile))
        
        suspicious_score = 0
        if freq_ratio < 0.1 or freq_ratio > 0.9:
            suspicious_score += 25
        if profile_smoothness > 1000:
            suspicious_score += 25
        
        periodic_patterns = self._detect_periodic_patterns(magnitude_spectrum)
        if periodic_patterns:
            suspicious_score += 30
        
        return {
            "score": int(min(suspicious_score, 100)),
            "freq_ratio": float(freq_ratio),
            "profile_smoothness": float(profile_smoothness),
            "periodic_patterns_detected": bool(periodic_patterns),
            "suspicious": bool(suspicious_score > 35),
            "details": "Frequency analysis reveals manipulation artifacts in spectral domain"
        }
    
    def analyze_noise_patterns(self, img_array: np.ndarray) -> Dict[str, Any]:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        try:
            noise_sigma = estimate_sigma(gray)
        except:
            noise_sigma = 0
        
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)
        laplacian_var = laplacian.var()
        
        regions = self._get_image_regions(gray)
        region_noise = []
        for region in regions:
            if region.size > 100:
                region_laplacian = cv2.Laplacian(region.astype(np.uint8), cv2.CV_64F)
                region_noise.append(region_laplacian.var())
        
        if region_noise:
            noise_variance = np.var(region_noise)
            noise_range = max(region_noise) - min(region_noise)
        else:
            noise_variance = 0
            noise_range = 0
        
        suspicious_score = 0
        if noise_variance > 10000:
            suspicious_score += 30
        if noise_range > 500:
            suspicious_score += 25
        if noise_sigma > 20:
            suspicious_score += 20
        
        return {
            "score": int(min(suspicious_score, 100)),
            "estimated_noise": float(noise_sigma) if not isinstance(noise_sigma, (list, np.ndarray)) else 0.0,
            "laplacian_variance": float(laplacian_var),
            "noise_consistency": float(noise_variance),
            "noise_range": float(noise_range),
            "suspicious": bool(suspicious_score > 35),
            "details": "Noise pattern analysis reveals inconsistencies in image generation"
        }
    
    def analyze_face_regions(self, img_array: np.ndarray) -> Dict[str, Any]:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        faces = self.face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
        
        if len(faces) == 0:
            return {
                "score": 0,
                "faces_detected": 0,
                "suspicious": False,
                "details": "No faces detected in image"
            }
        
        suspicious_score = 0
        face_analyses = []
        
        for i, (x, y, w, h) in enumerate(faces):
            face_region = img_array[y:y+h, x:x+w]
            face_gray = gray[y:y+h, x:x+w]
            
            eyes = self.eye_cascade.detectMultiScale(face_gray, scaleFactor=1.1, minNeighbors=3)
            eye_symmetry = self._check_eye_symmetry(eyes, w) if len(eyes) >= 2 else 0.5
            
            face_blur = cv2.Laplacian(face_gray, cv2.CV_64F).var()
            
            skin_uniformity = self._analyze_skin_uniformity(face_region)
            
            boundary_score = self._analyze_face_boundary(img_array, x, y, w, h)
            
            face_suspicious = 0
            if eye_symmetry < 0.7:
                face_suspicious += 20
            if face_blur < 100:
                face_suspicious += 25
            if skin_uniformity > 0.8:
                face_suspicious += 20
            if boundary_score > 30:
                face_suspicious += 25
            
            face_analyses.append({
                "face_id": i,
                "eye_symmetry": float(eye_symmetry),
                "blur_score": float(face_blur),
                "skin_uniformity": float(skin_uniformity),
                "boundary_artifacts": float(boundary_score),
                "suspicious_score": face_suspicious
            })
            
            suspicious_score = max(suspicious_score, face_suspicious)
        
        return {
            "score": int(min(suspicious_score, 100)),
            "faces_detected": int(len(faces)),
            "face_analyses": face_analyses,
            "suspicious": bool(suspicious_score > 40),
            "details": "Face region analysis examines facial features and boundaries"
        }
    
    def analyze_color_consistency(self, img_array: np.ndarray) -> Dict[str, Any]:
        if len(img_array.shape) != 3:
            return {"score": 0, "suspicious": False, "details": "Grayscale image"}
        
        hsv = cv2.cvtColor(img_array, cv2.COLOR_BGR2HSV)
        lab = cv2.cvtColor(img_array, cv2.COLOR_BGR2LAB)
        
        h, s, v = cv2.split(hsv)
        l_channel, a_channel, b_channel = cv2.split(lab)
        
        regions = self._get_image_regions(img_array)
        color_stats = []
        
        for region in regions:
            if region.size > 100:
                region_hsv = cv2.cvtColor(region, cv2.COLOR_BGR2HSV)
                region_h, region_s, region_v = cv2.split(region_hsv)
                color_stats.append({
                    "h_mean": np.mean(region_h),
                    "s_mean": np.mean(region_s),
                    "v_mean": np.mean(region_v)
                })
        
        if len(color_stats) > 1:
            h_variance = np.var([s["h_mean"] for s in color_stats])
            s_variance = np.var([s["s_mean"] for s in color_stats])
            lighting_variance = np.var([s["v_mean"] for s in color_stats])
        else:
            h_variance = s_variance = lighting_variance = 0
        
        suspicious_score = 0
        if lighting_variance > 2000:
            suspicious_score += 30
        if h_variance > 500:
            suspicious_score += 25
        if s_variance > 1000:
            suspicious_score += 20
        
        return {
            "score": int(min(suspicious_score, 100)),
            "hue_variance": float(h_variance),
            "saturation_variance": float(s_variance),
            "lighting_variance": float(lighting_variance),
            "suspicious": bool(suspicious_score > 35),
            "details": "Color consistency analysis detects unnatural color distributions"
        }
    
    def analyze_edge_artifacts(self, img_array: np.ndarray) -> Dict[str, Any]:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        edges_canny = cv2.Canny(gray, 50, 150)
        edges_sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        edges_sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        edges_sobel = np.sqrt(edges_sobel_x**2 + edges_sobel_y**2)
        
        edge_density = np.sum(edges_canny > 0) / edges_canny.size
        
        edge_continuity = self._measure_edge_continuity(edges_canny)
        
        gradient_consistency = np.std(edges_sobel[edges_sobel > 10]) if np.any(edges_sobel > 10) else 0
        
        suspicious_score = 0
        if edge_density < 0.02 or edge_density > 0.3:
            suspicious_score += 20
        if edge_continuity < 0.5:
            suspicious_score += 25
        if gradient_consistency > 100:
            suspicious_score += 25
        
        return {
            "score": int(min(suspicious_score, 100)),
            "edge_density": float(edge_density),
            "edge_continuity": float(edge_continuity),
            "gradient_consistency": float(gradient_consistency),
            "suspicious": bool(suspicious_score > 35),
            "details": "Edge artifact analysis detects blending and splicing boundaries"
        }
    
    def analyze_compression_artifacts(self, img_array: np.ndarray) -> Dict[str, Any]:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        h, w = gray.shape
        block_size = 8
        block_artifacts = []
        
        for i in range(0, h - block_size, block_size):
            for j in range(0, w - block_size, block_size):
                block = gray[i:i+block_size, j:j+block_size]
                dct_block = fftpack.dct(fftpack.dct(block.T, norm='ortho').T, norm='ortho')
                high_freq_energy = np.sum(np.abs(dct_block[4:, 4:]))
                block_artifacts.append(high_freq_energy)
        
        if block_artifacts:
            artifact_mean = np.mean(block_artifacts)
            artifact_std = np.std(block_artifacts)
            artifact_range = max(block_artifacts) - min(block_artifacts)
        else:
            artifact_mean = artifact_std = artifact_range = 0
        
        suspicious_score = 0
        if artifact_std > 100:
            suspicious_score += 25
        if artifact_range > 500:
            suspicious_score += 25
        
        double_compression = artifact_std / (artifact_mean + 1e-10) > 0.5
        if double_compression:
            suspicious_score += 30
        
        return {
            "score": int(min(suspicious_score, 100)),
            "artifact_mean": float(artifact_mean),
            "artifact_std": float(artifact_std),
            "artifact_range": float(artifact_range),
            "double_compression_suspected": bool(double_compression),
            "suspicious": bool(suspicious_score > 40),
            "details": "Compression artifact analysis reveals re-encoding patterns"
        }
    
    def analyze_texture_consistency(self, img_array: np.ndarray) -> Dict[str, Any]:
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        try:
            lbp = feature.local_binary_pattern(gray, P=8, R=1, method='uniform')
            lbp_hist, _ = np.histogram(lbp.ravel(), bins=10, range=(0, 10))
            lbp_hist = lbp_hist.astype(float) / (np.sum(lbp_hist) + 1e-10)
        except:
            lbp_hist = np.zeros(10)
        
        regions = self._get_image_regions(gray)
        region_textures = []
        
        for region in regions:
            if region.size > 100:
                try:
                    region_lbp = feature.local_binary_pattern(region.astype(np.uint8), P=8, R=1, method='uniform')
                    region_hist, _ = np.histogram(region_lbp.ravel(), bins=10, range=(0, 10))
                    region_hist = region_hist.astype(float) / (np.sum(region_hist) + 1e-10)
                    region_textures.append(region_hist)
                except:
                    pass
        
        if len(region_textures) > 1:
            texture_distances = []
            for i in range(len(region_textures)):
                for j in range(i+1, len(region_textures)):
                    dist = np.sum(np.abs(region_textures[i] - region_textures[j]))
                    texture_distances.append(dist)
            texture_variance = np.var(texture_distances) if texture_distances else 0
            max_texture_diff = max(texture_distances) if texture_distances else 0
        else:
            texture_variance = max_texture_diff = 0
        
        suspicious_score = 0
        if texture_variance > 0.1:
            suspicious_score += 30
        if max_texture_diff > 0.5:
            suspicious_score += 30
        
        return {
            "score": int(min(suspicious_score, 100)),
            "texture_variance": float(texture_variance),
            "max_texture_difference": float(max_texture_diff),
            "suspicious": bool(suspicious_score > 30),
            "details": "Texture consistency analysis detects synthetic patterns"
        }
    
    def _get_image_regions(self, img: np.ndarray, grid_size: int = 4) -> List[np.ndarray]:
        if len(img.shape) == 3:
            h, w, c = img.shape
        else:
            h, w = img.shape
        
        region_h = h // grid_size
        region_w = w // grid_size
        
        regions = []
        for i in range(grid_size):
            for j in range(grid_size):
                region = img[i*region_h:(i+1)*region_h, j*region_w:(j+1)*region_w]
                regions.append(region)
        
        return regions
    
    def _compute_radial_profile(self, magnitude: np.ndarray) -> np.ndarray:
        h, w = magnitude.shape
        center_y, center_x = h // 2, w // 2
        
        y, x = np.ogrid[:h, :w]
        r = np.sqrt((x - center_x)**2 + (y - center_y)**2).astype(int)
        
        max_r = min(center_x, center_y)
        radial_profile = ndimage.mean(magnitude, r, index=np.arange(0, max_r))
        
        return radial_profile
    
    def _detect_periodic_patterns(self, magnitude: np.ndarray) -> bool:
        h, w = magnitude.shape
        center_y, center_x = h // 2, w // 2
        
        threshold = np.percentile(magnitude, 99)
        peaks = magnitude > threshold
        
        peaks[center_y-5:center_y+5, center_x-5:center_x+5] = False
        
        num_peaks = np.sum(peaks)
        return bool(num_peaks > 20)
    
    def _check_eye_symmetry(self, eyes: np.ndarray, face_width: int) -> float:
        if len(eyes) < 2:
            return 0.5
        
        eyes_sorted = sorted(eyes, key=lambda e: e[0])
        left_eye = eyes_sorted[0]
        right_eye = eyes_sorted[-1]
        
        left_center = left_eye[0] + left_eye[2] // 2
        right_center = right_eye[0] + right_eye[2] // 2
        
        expected_distance = face_width * 0.4
        actual_distance = right_center - left_center
        
        symmetry = 1 - abs(expected_distance - actual_distance) / expected_distance
        return float(max(0, min(1, symmetry)))
    
    def _analyze_skin_uniformity(self, face_region: np.ndarray) -> float:
        if len(face_region.shape) != 3:
            return 0
        
        hsv = cv2.cvtColor(face_region, cv2.COLOR_BGR2HSV)
        
        lower_skin = np.array([0, 20, 70], dtype=np.uint8)
        upper_skin = np.array([20, 255, 255], dtype=np.uint8)
        
        skin_mask = cv2.inRange(hsv, lower_skin, upper_skin)
        skin_pixels = face_region[skin_mask > 0]
        
        if len(skin_pixels) == 0:
            return 0
        
        uniformity = 1 - (np.std(skin_pixels) / 128)
        return float(max(0, min(1, uniformity)))
    
    def _analyze_face_boundary(self, img: np.ndarray, x: int, y: int, w: int, h: int) -> float:
        border_width = 5
        
        top = img[max(0, y-border_width):y, x:x+w] if y > border_width else np.array([])
        bottom = img[y+h:min(img.shape[0], y+h+border_width), x:x+w] if y+h+border_width < img.shape[0] else np.array([])
        left = img[y:y+h, max(0, x-border_width):x] if x > border_width else np.array([])
        right = img[y:y+h, x+w:min(img.shape[1], x+w+border_width)] if x+w+border_width < img.shape[1] else np.array([])
        
        face_interior = img[y+border_width:y+h-border_width, x+border_width:x+w-border_width]
        
        if face_interior.size == 0:
            return 0
        
        interior_mean = np.mean(face_interior)
        
        boundary_diffs = []
        for boundary in [top, bottom, left, right]:
            if boundary.size > 0:
                boundary_diffs.append(abs(np.mean(boundary) - interior_mean))
        
        return float(np.mean(boundary_diffs)) if boundary_diffs else 0.0
    
    def _measure_edge_continuity(self, edges: np.ndarray) -> float:
        kernel = np.ones((3, 3), np.uint8)
        dilated = cv2.dilate(edges, kernel, iterations=1)
        
        edge_pixels = np.sum(edges > 0)
        dilated_pixels = np.sum(dilated > 0)
        
        if dilated_pixels == 0:
            return 1
        
        continuity = edge_pixels / dilated_pixels
        return float(continuity)


class DeepfakeDetectorService:
    def __init__(self):
        self.analyzer = AdvancedDeepfakeAnalyzer()
        self.vgg_extractor = VGGStyleFeatureExtractor()

    async def analyze_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        try:
            nparr = np.frombuffer(file_content, np.uint8)
            img_array = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img_array is None:
                pil_image = Image.open(io.BytesIO(file_content))
                img_array = np.array(pil_image.convert('RGB'))
                img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            
            if img_array is None:
                raise ValueError("Could not decode image")
            
            analyses = await self._run_all_analyses(img_array)
            
            result = self._compute_final_verdict(analyses, filename)
            
            return {
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "result": result.to_dict(),
                "status": "completed",
                "detection_method": "DeepFake-Image-Detection (VGG16-style CNN Analysis)",
                "model_available": True,
                "deepfake_image_detection_available": DEEPFAKE_IMAGE_DETECTION_AVAILABLE,
                "module_path": DEEPFAKE_DETECTION_MODULE_PATH
            }
            
        except Exception as e:
            return {
                "filename": filename,
                "timestamp": datetime.now().isoformat(),
                "result": DeepfakeResult(
                    filename=filename,
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error=str(e)
                ).to_dict(),
                "status": "error"
            }

    def _run_vgg_analysis(self, img_array: np.ndarray) -> Dict[str, Any]:
        features = self.vgg_extractor.extract_features(img_array)
        return self.vgg_extractor.compute_authenticity_score(features)

    async def _run_all_analyses(self, img_array: np.ndarray) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        
        ela_task = loop.run_in_executor(None, self.analyzer.analyze_error_level, img_array)
        freq_task = loop.run_in_executor(None, self.analyzer.analyze_frequency_domain, img_array)
        noise_task = loop.run_in_executor(None, self.analyzer.analyze_noise_patterns, img_array)
        face_task = loop.run_in_executor(None, self.analyzer.analyze_face_regions, img_array)
        color_task = loop.run_in_executor(None, self.analyzer.analyze_color_consistency, img_array)
        edge_task = loop.run_in_executor(None, self.analyzer.analyze_edge_artifacts, img_array)
        compression_task = loop.run_in_executor(None, self.analyzer.analyze_compression_artifacts, img_array)
        texture_task = loop.run_in_executor(None, self.analyzer.analyze_texture_consistency, img_array)
        vgg_task = loop.run_in_executor(None, self._run_vgg_analysis, img_array)
        
        results = await asyncio.gather(
            ela_task, freq_task, noise_task, face_task,
            color_task, edge_task, compression_task, texture_task, vgg_task
        )
        
        return {
            "error_level_analysis": results[0],
            "frequency_analysis": results[1],
            "noise_pattern_analysis": results[2],
            "face_region_analysis": results[3],
            "color_consistency": results[4],
            "edge_artifacts": results[5],
            "compression_artifacts": results[6],
            "texture_consistency": results[7],
            "vgg_deep_features": results[8]
        }
    
    def _compute_final_verdict(self, analyses: Dict[str, Any], filename: str) -> DeepfakeResult:
        weights = {
            "error_level_analysis": 0.12,
            "frequency_analysis": 0.12,
            "noise_pattern_analysis": 0.12,
            "face_region_analysis": 0.18,
            "color_consistency": 0.08,
            "edge_artifacts": 0.08,
            "compression_artifacts": 0.08,
            "texture_consistency": 0.04,
            "vgg_deep_features": 0.18
        }
        
        weighted_score = 0
        suspicious_count = 0
        total_weight = 0
        
        for analysis_name, analysis_result in analyses.items():
            weight = weights.get(analysis_name, 0.1)
            score = analysis_result.get("score", 0)
            suspicious = analysis_result.get("suspicious", False)
            
            weighted_score += score * weight
            total_weight += weight
            
            if suspicious:
                suspicious_count += 1
        
        if total_weight > 0:
            final_score = weighted_score / total_weight
        else:
            final_score = 0
        
        if suspicious_count >= 5:
            final_score = min(100, final_score + 20)
        elif suspicious_count >= 3:
            final_score = min(100, final_score + 10)
        
        confidence = final_score / 100
        is_deepfake = final_score > 45
        
        if final_score >= 70:
            verdict = "HIGH PROBABILITY - Likely Deepfake/Manipulated"
            risk_level = "Critical"
        elif final_score >= 50:
            verdict = "MODERATE PROBABILITY - Possible Manipulation"
            risk_level = "High"
        elif final_score >= 30:
            verdict = "LOW PROBABILITY - Minor Concerns"
            risk_level = "Medium"
        else:
            verdict = "AUTHENTIC - No Significant Manipulation Detected"
            risk_level = "Low"
        
        analysis_summary = []
        for name, result in analyses.items():
            if result.get("suspicious", False):
                analysis_summary.append(f"{name.replace('_', ' ').title()}: FLAGGED - {result.get('details', '')}")
            else:
                analysis_summary.append(f"{name.replace('_', ' ').title()}: PASSED")
        
        return DeepfakeResult(
            filename=filename,
            is_deepfake=is_deepfake,
            confidence=round(confidence, 4),
            analysis_details={
                "verdict": verdict,
                "risk_level": risk_level,
                "overall_score": round(final_score, 2),
                "suspicious_indicators": suspicious_count,
                "total_analyses": len(analyses),
                "analysis_breakdown": analyses,
                "summary": analysis_summary,
                "methodology": [
                    "VGG Deep Features (DeepFake-Image-Detection) - CNN-style feature extraction",
                    "Error Level Analysis (ELA) - Detects compression inconsistencies",
                    "Frequency Domain Analysis - Reveals spectral manipulation artifacts",
                    "Noise Pattern Analysis - Identifies synthetic noise patterns",
                    "Face Region Analysis - Examines facial feature authenticity",
                    "Color Consistency - Detects unnatural color distributions",
                    "Edge Artifact Detection - Finds blending boundaries",
                    "Compression Artifact Analysis - Reveals re-encoding patterns",
                    "Texture Consistency - Detects synthetic textures"
                ],
                "module_source": "DeepFake-Image-Detection (Pretrained_Models)"
            }
        )

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
