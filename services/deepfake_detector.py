import asyncio
import os
import base64
import tempfile
import io
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np
from PIL import Image, ImageFilter, ImageStat
import cv2
from scipy import fftpack, ndimage, stats, signal
from scipy.ndimage import gaussian_filter, sobel
from skimage import feature, filters, measure, color, exposure
from skimage.restoration import estimate_sigma
from skimage.feature import graycomatrix, graycoprops
import struct
import math

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


class AdvancedDeepfakeAnalyzer:
    """
    State-of-the-art deepfake detection using multiple forensic techniques:
    1. Error Level Analysis (ELA) - Detects compression inconsistencies
    2. Frequency Domain Analysis (FFT/DCT) - Reveals GAN artifacts
    3. Face Symmetry & Landmark Analysis - Detects unnatural faces
    4. Noise Pattern Analysis - Identifies AI-generated noise signatures
    5. Color Channel Analysis - Detects chrominance anomalies
    6. JPEG Ghost Detection - Finds double compression
    7. Texture Gradient Analysis - Reveals blending artifacts
    8. Edge Coherence Analysis - Detects boundary manipulation
    9. Statistical Feature Analysis - GLCM texture features
    10. Spectral Analysis - Wavelet-based artifact detection
    """
    
    def __init__(self):
        self.face_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        )
        self.eye_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_eye.xml'
        )
        self.profile_cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + 'haarcascade_profileface.xml'
        )
    
    def analyze_error_level(self, img_array: np.ndarray, quality: int = 95) -> Dict[str, Any]:
        """
        Enhanced ELA - Detects regions with different compression levels.
        Deepfakes often have inconsistent compression in face regions.
        """
        scores = []
        
        for q in [95, 90, 85, 75]:
            is_success, buffer = cv2.imencode('.jpg', img_array, [cv2.IMWRITE_JPEG_QUALITY, q])
            if not is_success:
                continue
            
            recompressed = cv2.imdecode(np.frombuffer(buffer, np.uint8), cv2.IMREAD_COLOR)
            ela_image = cv2.absdiff(img_array, recompressed)
            
            ela_enhanced = (ela_image * 20).clip(0, 255).astype(np.uint8)
            ela_gray = cv2.cvtColor(ela_enhanced, cv2.COLOR_BGR2GRAY)
            
            mean_ela = np.mean(ela_gray)
            std_ela = np.std(ela_gray)
            max_ela = np.max(ela_gray)
            
            h, w = ela_gray.shape
            regions = []
            grid = 8
            for i in range(grid):
                for j in range(grid):
                    region = ela_gray[i*h//grid:(i+1)*h//grid, j*w//grid:(j+1)*w//grid]
                    regions.append(np.mean(region))
            
            region_variance = np.var(regions)
            region_range = max(regions) - min(regions)
            
            score = 0
            if mean_ela > 8:
                score += 15
            if mean_ela > 15:
                score += 15
            if std_ela > 12:
                score += 15
            if region_variance > 50:
                score += 20
            if region_range > 30:
                score += 20
            if max_ela > 150:
                score += 15
                
            scores.append(score)
        
        final_score = int(np.mean(scores)) if scores else 0
        
        return {
            "score": min(final_score, 100),
            "mean_ela": float(mean_ela) if 'mean_ela' in dir() else 0,
            "std_ela": float(std_ela) if 'std_ela' in dir() else 0,
            "region_variance": float(region_variance) if 'region_variance' in dir() else 0,
            "suspicious": final_score > 35,
            "details": "ELA detects compression inconsistencies typical in manipulated images"
        }
    
    def analyze_frequency_domain(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Advanced frequency analysis using FFT and DCT.
        GANs leave distinctive patterns in the frequency domain.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        gray = gray.astype(np.float64)
        
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        magnitude = np.abs(f_shift)
        phase = np.angle(f_shift)
        
        log_magnitude = np.log1p(magnitude)
        
        h, w = gray.shape
        cy, cx = h // 2, w // 2
        
        y, x = np.ogrid[:h, :w]
        r = np.sqrt((x - cx)**2 + (y - cy)**2)
        
        low_mask = r < min(h, w) * 0.1
        mid_mask = (r >= min(h, w) * 0.1) & (r < min(h, w) * 0.3)
        high_mask = r >= min(h, w) * 0.3
        
        low_energy = np.mean(magnitude[low_mask])
        mid_energy = np.mean(magnitude[mid_mask])
        high_energy = np.mean(magnitude[high_mask])
        
        total_energy = low_energy + mid_energy + high_energy
        low_ratio = low_energy / total_energy if total_energy > 0 else 0
        high_ratio = high_energy / total_energy if total_energy > 0 else 0
        
        azimuthal_profile = []
        for angle in range(0, 360, 10):
            rad = np.deg2rad(angle)
            line_x = cx + np.arange(0, min(cx, cy)) * np.cos(rad)
            line_y = cy + np.arange(0, min(cx, cy)) * np.sin(rad)
            line_x = line_x.astype(int).clip(0, w-1)
            line_y = line_y.astype(int).clip(0, h-1)
            azimuthal_profile.append(np.mean(log_magnitude[line_y, line_x]))
        
        azimuthal_std = np.std(azimuthal_profile)
        
        dct_coeffs = fftpack.dct(fftpack.dct(gray.T, norm='ortho').T, norm='ortho')
        dct_high_freq = np.abs(dct_coeffs[h//2:, w//2:])
        dct_periodicity = np.std(dct_high_freq)
        
        score = 0
        
        if high_ratio < 0.01:
            score += 25
        if high_ratio > 0.15:
            score += 20
        
        if azimuthal_std < 0.5:
            score += 30
        
        if dct_periodicity > 50:
            score += 25
        
        return {
            "score": min(int(score), 100),
            "low_freq_ratio": float(low_ratio),
            "high_freq_ratio": float(high_ratio),
            "azimuthal_uniformity": float(azimuthal_std),
            "dct_periodicity": float(dct_periodicity),
            "suspicious": score > 35,
            "details": "Frequency analysis reveals GAN fingerprints and spectral anomalies"
        }
    
    def analyze_noise_patterns(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Advanced noise analysis - AI-generated images have distinctive noise patterns.
        Real photos have natural sensor noise, while AI images have synthetic patterns.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        gray_float = gray.astype(np.float64)
        
        denoised = cv2.GaussianBlur(gray, (5, 5), 0)
        noise = gray_float - denoised.astype(np.float64)
        
        noise_mean = np.mean(np.abs(noise))
        noise_std = np.std(noise)
        
        try:
            sigma_est = estimate_sigma(gray, channel_axis=None)
        except:
            sigma_est = noise_std
        
        h, w = gray.shape
        grid = 6
        region_noise = []
        for i in range(grid):
            for j in range(grid):
                region = noise[i*h//grid:(i+1)*h//grid, j*w//grid:(j+1)*w//grid]
                region_noise.append(np.std(region))
        
        noise_uniformity = np.std(region_noise) / (np.mean(region_noise) + 1e-10)
        
        f_noise = np.fft.fft2(noise)
        f_noise_mag = np.abs(np.fft.fftshift(f_noise))
        noise_spectrum_std = np.std(f_noise_mag)
        
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)
        laplacian_var = laplacian.var()
        
        score = 0
        
        if noise_uniformity < 0.15:
            score += 35
        
        if noise_std < 2:
            score += 25
        elif noise_std > 25:
            score += 15
        
        if laplacian_var < 50:
            score += 25
        
        return {
            "score": min(int(score), 100),
            "noise_std": float(noise_std),
            "noise_uniformity": float(noise_uniformity),
            "estimated_sigma": float(sigma_est) if isinstance(sigma_est, (int, float)) else float(np.mean(sigma_est)),
            "laplacian_variance": float(laplacian_var),
            "suspicious": score > 35,
            "details": "AI-generated images often have unnaturally uniform or absent noise patterns"
        }
    
    def analyze_face_regions(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Comprehensive face analysis for deepfake detection:
        - Eye symmetry and positioning
        - Skin texture consistency
        - Face boundary artifacts
        - Facial feature proportions
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        faces = self.face_cascade.detectMultiScale(gray, scaleFactor=1.05, minNeighbors=5, minSize=(50, 50))
        
        if len(faces) == 0:
            profiles = self.profile_cascade.detectMultiScale(gray, scaleFactor=1.05, minNeighbors=5)
            if len(profiles) == 0:
                return {
                    "score": 0,
                    "faces_detected": 0,
                    "suspicious": False,
                    "details": "No faces detected"
                }
            faces = profiles
        
        max_score = 0
        face_analyses = []
        
        for idx, (x, y, w, h) in enumerate(faces):
            padding = int(w * 0.1)
            x1, y1 = max(0, x - padding), max(0, y - padding)
            x2, y2 = min(img_array.shape[1], x + w + padding), min(img_array.shape[0], y + h + padding)
            
            face_region = img_array[y1:y2, x1:x2]
            face_gray = gray[y1:y2, x1:x2]
            
            eyes = self.eye_cascade.detectMultiScale(face_gray, scaleFactor=1.1, minNeighbors=3, minSize=(15, 15))
            
            eye_score = 0
            if len(eyes) == 2:
                eyes_sorted = sorted(eyes, key=lambda e: e[0])
                left_eye, right_eye = eyes_sorted[0], eyes_sorted[1]
                
                left_center = (left_eye[0] + left_eye[2]//2, left_eye[1] + left_eye[3]//2)
                right_center = (right_eye[0] + right_eye[2]//2, right_eye[1] + right_eye[3]//2)
                
                eye_y_diff = abs(left_center[1] - right_center[1]) / h
                if eye_y_diff > 0.08:
                    eye_score += 25
                
                eye_size_ratio = min(left_eye[2], right_eye[2]) / max(left_eye[2], right_eye[2])
                if eye_size_ratio < 0.7:
                    eye_score += 20
            elif len(eyes) != 2:
                eye_score += 15
            
            blur_score = cv2.Laplacian(face_gray, cv2.CV_64F).var()
            blur_flag = 0
            if blur_score < 100:
                blur_flag = 25
            
            if len(face_region.shape) == 3:
                hsv = cv2.cvtColor(face_region, cv2.COLOR_BGR2HSV)
                h_channel, s_channel, v_channel = cv2.split(hsv)
                
                skin_mask = (h_channel >= 0) & (h_channel <= 25) & (s_channel >= 30) & (s_channel <= 180)
                if np.sum(skin_mask) > 100:
                    skin_h = h_channel[skin_mask]
                    skin_s = s_channel[skin_mask]
                    skin_uniformity = (np.std(skin_h) + np.std(skin_s)) / 2
                else:
                    skin_uniformity = 50
            else:
                skin_uniformity = 50
            
            skin_score = 0
            if skin_uniformity < 8:
                skin_score = 30
            
            boundary_region = 10
            top_boundary = gray[max(0,y-boundary_region):y, x:x+w] if y > boundary_region else np.array([])
            bottom_boundary = gray[y+h:min(gray.shape[0],y+h+boundary_region), x:x+w]
            face_edge = gray[y:y+boundary_region, x:x+w] if boundary_region < h else gray[y:y+h, x:x+w]
            
            boundary_score = 0
            if top_boundary.size > 0 and face_edge.size > 0:
                boundary_diff = abs(np.mean(top_boundary) - np.mean(face_edge))
                if boundary_diff > 30:
                    boundary_score = 25
            
            face_total = eye_score + blur_flag + skin_score + boundary_score
            max_score = max(max_score, face_total)
            
            face_analyses.append({
                "face_id": idx,
                "eye_score": eye_score,
                "blur_score": float(blur_score),
                "skin_uniformity": float(skin_uniformity),
                "boundary_artifact_score": boundary_score,
                "total_score": face_total
            })
        
        return {
            "score": min(int(max_score), 100),
            "faces_detected": len(faces),
            "face_analyses": face_analyses,
            "suspicious": max_score > 40,
            "details": "Face analysis checks for eye symmetry, skin texture, and boundary artifacts"
        }
    
    def analyze_color_channels(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Advanced color analysis - Deepfakes often have color channel inconsistencies.
        Checks for chrominance anomalies and color bleeding.
        """
        if len(img_array.shape) != 3:
            return {"score": 0, "suspicious": False, "details": "Grayscale image"}
        
        b, g, r = cv2.split(img_array)
        
        rb_corr = np.corrcoef(r.flatten(), b.flatten())[0, 1]
        rg_corr = np.corrcoef(r.flatten(), g.flatten())[0, 1]
        gb_corr = np.corrcoef(g.flatten(), b.flatten())[0, 1]
        
        ycrcb = cv2.cvtColor(img_array, cv2.COLOR_BGR2YCrCb)
        y, cr, cb = cv2.split(ycrcb)
        
        cr_edges = cv2.Canny(cr, 50, 150)
        cb_edges = cv2.Canny(cb, 50, 150)
        y_edges = cv2.Canny(y, 50, 150)
        
        cr_edge_density = np.sum(cr_edges > 0) / cr_edges.size
        cb_edge_density = np.sum(cb_edges > 0) / cb_edges.size
        y_edge_density = np.sum(y_edges > 0) / y_edges.size
        
        chroma_luma_ratio = (cr_edge_density + cb_edge_density) / (y_edge_density + 1e-10)
        
        lab = cv2.cvtColor(img_array, cv2.COLOR_BGR2LAB)
        l_chan, a_chan, b_chan = cv2.split(lab)
        
        a_range = np.max(a_chan) - np.min(a_chan)
        b_range = np.max(b_chan) - np.min(b_chan)
        
        score = 0
        
        if abs(rb_corr) > 0.98:
            score += 20
        if abs(rg_corr) > 0.98:
            score += 15
        
        if chroma_luma_ratio > 1.5:
            score += 25
        elif chroma_luma_ratio < 0.1:
            score += 20
        
        if a_range < 30 and b_range < 30:
            score += 20
        
        return {
            "score": min(int(score), 100),
            "rb_correlation": float(rb_corr),
            "rg_correlation": float(rg_corr),
            "chroma_luma_ratio": float(chroma_luma_ratio),
            "suspicious": score > 35,
            "details": "Color analysis detects chrominance anomalies in manipulated images"
        }
    
    def analyze_jpeg_artifacts(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        JPEG ghost and double compression detection.
        Manipulated images often show signs of multiple JPEG compressions.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        h, w = gray.shape
        block_size = 8
        block_dcts = []
        
        for i in range(0, h - block_size, block_size):
            for j in range(0, w - block_size, block_size):
                block = gray[i:i+block_size, j:j+block_size].astype(np.float64)
                dct = fftpack.dct(fftpack.dct(block.T, norm='ortho').T, norm='ortho')
                block_dcts.append(dct)
        
        if not block_dcts:
            return {"score": 0, "suspicious": False, "details": "Image too small for analysis"}
        
        ac_coeffs = []
        for dct in block_dcts:
            ac_coeffs.extend(dct.flatten()[1:])
        
        ac_coeffs = np.array(ac_coeffs)
        
        hist, bins = np.histogram(ac_coeffs, bins=100, range=(-50, 50))
        hist = hist.astype(float)
        hist_normalized = hist / (np.sum(hist) + 1e-10)
        
        double_peaks = 0
        for i in range(2, len(hist) - 2):
            if hist[i] > hist[i-1] and hist[i] > hist[i+1]:
                if hist[i] > hist[i-2] and hist[i] > hist[i+2]:
                    double_peaks += 1
        
        blocking_artifacts = []
        for i in range(block_size, h - block_size, block_size):
            row_diff = np.mean(np.abs(gray[i, :].astype(float) - gray[i-1, :].astype(float)))
            blocking_artifacts.append(row_diff)
        
        blocking_score = np.std(blocking_artifacts) if blocking_artifacts else 0
        
        score = 0
        if double_peaks > 10:
            score += 30
        if blocking_score > 5:
            score += 25
        if blocking_score > 10:
            score += 20
        
        return {
            "score": min(int(score), 100),
            "double_peaks": double_peaks,
            "blocking_artifacts": float(blocking_score),
            "suspicious": score > 35,
            "details": "JPEG analysis detects double compression and blocking artifacts"
        }
    
    def analyze_texture_gradients(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Texture gradient analysis using GLCM features.
        Detects unnatural texture patterns common in AI-generated images.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        gray_scaled = (gray / 16).astype(np.uint8)
        
        try:
            distances = [1, 2, 4]
            angles = [0, np.pi/4, np.pi/2, 3*np.pi/4]
            
            glcm = graycomatrix(gray_scaled, distances=distances, angles=angles, levels=16, symmetric=True, normed=True)
            
            contrast = graycoprops(glcm, 'contrast').mean()
            dissimilarity = graycoprops(glcm, 'dissimilarity').mean()
            homogeneity = graycoprops(glcm, 'homogeneity').mean()
            energy = graycoprops(glcm, 'energy').mean()
            correlation = graycoprops(glcm, 'correlation').mean()
            
        except Exception as e:
            return {"score": 0, "suspicious": False, "details": f"GLCM analysis failed: {str(e)}"}
        
        score = 0
        
        if homogeneity > 0.8:
            score += 25
        
        if energy > 0.3:
            score += 20
        
        if contrast < 0.5:
            score += 25
        
        if correlation > 0.98:
            score += 20
        
        return {
            "score": min(int(score), 100),
            "contrast": float(contrast),
            "homogeneity": float(homogeneity),
            "energy": float(energy),
            "correlation": float(correlation),
            "suspicious": score > 35,
            "details": "Texture analysis reveals unnatural patterns in AI-generated images"
        }
    
    def analyze_edge_coherence(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Edge coherence analysis - detects blending boundaries and manipulation edges.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        edges_canny = cv2.Canny(gray, 50, 150)
        edges_canny_low = cv2.Canny(gray, 30, 100)
        edges_canny_high = cv2.Canny(gray, 80, 200)
        
        sobel_x = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        sobel_y = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        
        gradient_magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
        gradient_direction = np.arctan2(sobel_y, sobel_x)
        
        edge_density = np.sum(edges_canny > 0) / edges_canny.size
        
        edge_strength = gradient_magnitude[edges_canny > 0] if np.any(edges_canny > 0) else np.array([0])
        edge_strength_std = np.std(edge_strength)
        edge_strength_mean = np.mean(edge_strength)
        
        edge_diff = np.abs(edges_canny_low.astype(float) - edges_canny_high.astype(float))
        edge_consistency = np.mean(edge_diff)
        
        contours, _ = cv2.findContours(edges_canny, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        short_contours = sum(1 for c in contours if cv2.arcLength(c, False) < 20)
        total_contours = len(contours) if len(contours) > 0 else 1
        fragmentation = short_contours / total_contours
        
        score = 0
        
        if edge_strength_std / (edge_strength_mean + 1e-10) > 1.5:
            score += 25
        
        if fragmentation > 0.7:
            score += 25
        
        if edge_consistency > 30:
            score += 20
        
        if edge_density < 0.02:
            score += 20
        
        return {
            "score": min(int(score), 100),
            "edge_density": float(edge_density),
            "edge_strength_variation": float(edge_strength_std / (edge_strength_mean + 1e-10)),
            "edge_fragmentation": float(fragmentation),
            "suspicious": score > 35,
            "details": "Edge analysis detects blending boundaries and manipulation artifacts"
        }
    
    def analyze_statistical_features(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Statistical feature analysis - checks for statistical anomalies
        that indicate AI generation or manipulation.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        
        hist, _ = np.histogram(gray.flatten(), bins=256, range=(0, 256))
        hist_normalized = hist / np.sum(hist)
        
        entropy = -np.sum(hist_normalized * np.log2(hist_normalized + 1e-10))
        
        skewness = stats.skew(gray.flatten())
        kurtosis = stats.kurtosis(gray.flatten())
        
        benford_first_digits = []
        for val in gray.flatten():
            if val > 0:
                first_digit = int(str(val)[0])
                benford_first_digits.append(first_digit)
        
        if benford_first_digits:
            digit_counts = np.bincount(benford_first_digits, minlength=10)[1:]
            digit_freq = digit_counts / np.sum(digit_counts)
            
            expected_benford = np.log10(1 + 1/np.arange(1, 10))
            benford_deviation = np.sum(np.abs(digit_freq - expected_benford))
        else:
            benford_deviation = 0
        
        sorted_hist = np.sort(hist)[::-1]
        zipf_deviation = np.std(sorted_hist[:10] / (np.arange(1, 11) * sorted_hist[0] + 1e-10))
        
        score = 0
        
        if entropy < 5 or entropy > 7.8:
            score += 20
        
        if abs(skewness) > 1.5:
            score += 15
        if abs(kurtosis) > 3:
            score += 15
        
        if benford_deviation > 0.3:
            score += 25
        
        return {
            "score": min(int(score), 100),
            "entropy": float(entropy),
            "skewness": float(skewness),
            "kurtosis": float(kurtosis),
            "benford_deviation": float(benford_deviation),
            "suspicious": score > 35,
            "details": "Statistical analysis reveals distribution anomalies in AI-generated images"
        }
    
    def analyze_spectral_features(self, img_array: np.ndarray) -> Dict[str, Any]:
        """
        Spectral analysis using multi-scale decomposition.
        Detects artifacts across different frequency bands.
        """
        gray = cv2.cvtColor(img_array, cv2.COLOR_BGR2GRAY) if len(img_array.shape) == 3 else img_array
        gray = gray.astype(np.float64)
        
        levels = []
        current = gray
        for i in range(4):
            blurred = cv2.GaussianBlur(current, (5, 5), 0)
            detail = current - blurred
            levels.append(detail)
            current = cv2.resize(blurred, (blurred.shape[1]//2, blurred.shape[0]//2)) if blurred.shape[0] > 10 and blurred.shape[1] > 10 else blurred
        
        level_energies = [np.sum(level**2) / level.size for level in levels]
        
        if len(level_energies) > 1:
            energy_ratios = [level_energies[i] / (level_energies[i+1] + 1e-10) for i in range(len(level_energies)-1)]
            energy_consistency = np.std(energy_ratios)
        else:
            energy_consistency = 0
        
        level_stds = [np.std(level) for level in levels]
        std_ratio = level_stds[0] / (level_stds[-1] + 1e-10) if len(level_stds) > 1 else 1
        
        score = 0
        
        if energy_consistency > 5:
            score += 25
        
        if std_ratio < 1 or std_ratio > 20:
            score += 25
        
        if len(level_energies) > 0 and level_energies[0] < 0.01:
            score += 20
        
        return {
            "score": min(int(score), 100),
            "energy_consistency": float(energy_consistency),
            "detail_ratio": float(std_ratio),
            "level_energies": [float(e) for e in level_energies[:4]],
            "suspicious": score > 35,
            "details": "Spectral analysis reveals multi-scale artifacts in manipulated images"
        }


class DeepfakeService:
    def __init__(self):
        self.analyzer = AdvancedDeepfakeAnalyzer()
        self.analysis_weights = {
            "error_level": 1.2,
            "frequency_domain": 1.3,
            "noise_patterns": 1.2,
            "face_regions": 1.5,
            "color_channels": 1.0,
            "jpeg_artifacts": 1.1,
            "texture_gradients": 1.1,
            "edge_coherence": 1.0,
            "statistical_features": 0.9,
            "spectral_features": 1.0
        }
    
    async def analyze_base64(self, file_data: str, filename: str) -> Dict[str, Any]:
        try:
            if ',' in file_data:
                file_data = file_data.split(',')[1]
            
            image_bytes = base64.b64decode(file_data)
            return await self.analyze_file(image_bytes, filename)
        except Exception as e:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error=str(e)
            ).to_dict()
    
    async def analyze_file(self, file_bytes: bytes, filename: str) -> Dict[str, Any]:
        try:
            nparr = np.frombuffer(file_bytes, np.uint8)
            img_array = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if img_array is None:
                pil_image = Image.open(io.BytesIO(file_bytes))
                img_array = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            if img_array is None:
                return DeepfakeResult(
                    filename=filename,
                    is_deepfake=None,
                    confidence=None,
                    analysis_details={},
                    error="Could not decode image"
                ).to_dict()
            
            min_dim = min(img_array.shape[0], img_array.shape[1])
            max_dim = max(img_array.shape[0], img_array.shape[1])
            
            if max_dim > 2000:
                scale = 2000 / max_dim
                img_array = cv2.resize(img_array, None, fx=scale, fy=scale)
            
            loop = asyncio.get_event_loop()
            
            ela_task = loop.run_in_executor(None, self.analyzer.analyze_error_level, img_array)
            freq_task = loop.run_in_executor(None, self.analyzer.analyze_frequency_domain, img_array)
            noise_task = loop.run_in_executor(None, self.analyzer.analyze_noise_patterns, img_array)
            face_task = loop.run_in_executor(None, self.analyzer.analyze_face_regions, img_array)
            color_task = loop.run_in_executor(None, self.analyzer.analyze_color_channels, img_array)
            jpeg_task = loop.run_in_executor(None, self.analyzer.analyze_jpeg_artifacts, img_array)
            texture_task = loop.run_in_executor(None, self.analyzer.analyze_texture_gradients, img_array)
            edge_task = loop.run_in_executor(None, self.analyzer.analyze_edge_coherence, img_array)
            stats_task = loop.run_in_executor(None, self.analyzer.analyze_statistical_features, img_array)
            spectral_task = loop.run_in_executor(None, self.analyzer.analyze_spectral_features, img_array)
            
            results = await asyncio.gather(
                ela_task, freq_task, noise_task, face_task, color_task,
                jpeg_task, texture_task, edge_task, stats_task, spectral_task,
                return_exceptions=True
            )
            
            analysis_results = {
                "error_level": results[0] if not isinstance(results[0], Exception) else {"score": 0, "error": str(results[0])},
                "frequency_domain": results[1] if not isinstance(results[1], Exception) else {"score": 0, "error": str(results[1])},
                "noise_patterns": results[2] if not isinstance(results[2], Exception) else {"score": 0, "error": str(results[2])},
                "face_regions": results[3] if not isinstance(results[3], Exception) else {"score": 0, "error": str(results[3])},
                "color_channels": results[4] if not isinstance(results[4], Exception) else {"score": 0, "error": str(results[4])},
                "jpeg_artifacts": results[5] if not isinstance(results[5], Exception) else {"score": 0, "error": str(results[5])},
                "texture_gradients": results[6] if not isinstance(results[6], Exception) else {"score": 0, "error": str(results[6])},
                "edge_coherence": results[7] if not isinstance(results[7], Exception) else {"score": 0, "error": str(results[7])},
                "statistical_features": results[8] if not isinstance(results[8], Exception) else {"score": 0, "error": str(results[8])},
                "spectral_features": results[9] if not isinstance(results[9], Exception) else {"score": 0, "error": str(results[9])}
            }
            
            weighted_score = 0
            total_weight = 0
            suspicious_count = 0
            
            for key, result in analysis_results.items():
                if isinstance(result, dict) and "score" in result:
                    weight = self.analysis_weights.get(key, 1.0)
                    weighted_score += result["score"] * weight
                    total_weight += weight
                    if result.get("suspicious", False):
                        suspicious_count += 1
            
            if total_weight > 0:
                final_score = weighted_score / total_weight
            else:
                final_score = 0
            
            if suspicious_count >= 6:
                final_score = min(final_score * 1.3, 100)
            elif suspicious_count >= 4:
                final_score = min(final_score * 1.15, 100)
            
            if final_score >= 60:
                is_deepfake = True
                verdict = "LIKELY FAKE/MANIPULATED"
            elif final_score >= 40:
                is_deepfake = True
                verdict = "POSSIBLY MANIPULATED"
            elif final_score >= 25:
                is_deepfake = None
                verdict = "UNCERTAIN - NEEDS REVIEW"
            else:
                is_deepfake = False
                verdict = "LIKELY AUTHENTIC"
            
            confidence = min(abs(final_score - 50) * 2, 100)
            
            return DeepfakeResult(
                filename=filename,
                is_deepfake=is_deepfake,
                confidence=round(confidence, 2),
                analysis_details={
                    "overall_score": round(final_score, 2),
                    "verdict": verdict,
                    "suspicious_indicators": suspicious_count,
                    "total_analyses": len(analysis_results),
                    "analyses": analysis_results,
                    "interpretation": self._get_interpretation(final_score, suspicious_count, analysis_results)
                }
            ).to_dict()
            
        except Exception as e:
            return DeepfakeResult(
                filename=filename,
                is_deepfake=None,
                confidence=None,
                analysis_details={},
                error=str(e)
            ).to_dict()
    
    def _get_interpretation(self, score: float, suspicious_count: int, analyses: Dict) -> str:
        findings = []
        
        if analyses.get("error_level", {}).get("suspicious"):
            findings.append("Compression inconsistencies detected (common in edited images)")
        
        if analyses.get("frequency_domain", {}).get("suspicious"):
            findings.append("Unusual frequency patterns (potential GAN artifacts)")
        
        if analyses.get("noise_patterns", {}).get("suspicious"):
            findings.append("Abnormal noise distribution (typical of AI generation)")
        
        if analyses.get("face_regions", {}).get("suspicious"):
            findings.append("Face region anomalies detected")
        
        if analyses.get("color_channels", {}).get("suspicious"):
            findings.append("Color channel inconsistencies found")
        
        if analyses.get("jpeg_artifacts", {}).get("suspicious"):
            findings.append("Signs of double JPEG compression")
        
        if analyses.get("texture_gradients", {}).get("suspicious"):
            findings.append("Unnatural texture patterns detected")
        
        if analyses.get("edge_coherence", {}).get("suspicious"):
            findings.append("Edge artifacts suggesting manipulation")
        
        if findings:
            return "Key findings: " + "; ".join(findings)
        elif score < 25:
            return "No significant manipulation indicators found. Image appears authentic."
        else:
            return "Some minor anomalies detected but within normal range."


deepfake_service = DeepfakeService()
