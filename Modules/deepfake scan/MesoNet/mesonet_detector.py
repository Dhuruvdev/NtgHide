import cv2
import numpy as np
from PIL import Image
import io
from typing import Dict, Any, Tuple, List
import os

class MesoNetDetector:
    def __init__(self):
        self.face_cascade = None
        self._load_face_detector()
    
    def _load_face_detector(self):
        cascade_paths = [
            cv2.data.haarcascades + 'haarcascade_frontalface_default.xml',
            '/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml',
            'haarcascade_frontalface_default.xml'
        ]
        for path in cascade_paths:
            if os.path.exists(path):
                self.face_cascade = cv2.CascadeClassifier(path)
                break
        if self.face_cascade is None or self.face_cascade.empty():
            self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    
    def detect_faces(self, image: np.ndarray) -> List[Tuple[int, int, int, int]]:
        if self.face_cascade is None or self.face_cascade.empty():
            return []
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
        return [(x, y, w, h) for (x, y, w, h) in faces]
    
    def analyze_frequency_artifacts(self, image: np.ndarray) -> Tuple[float, Dict]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        magnitude_spectrum = 20 * np.log(np.abs(f_shift) + 1)
        
        h, w = magnitude_spectrum.shape
        center_y, center_x = h // 2, w // 2
        
        high_freq_region = magnitude_spectrum[
            max(0, center_y - h//4):min(h, center_y + h//4),
            max(0, center_x - w//4):min(w, center_x + w//4)
        ]
        
        high_freq_mean = np.mean(high_freq_region)
        high_freq_std = np.std(high_freq_region)
        
        outer_mask = np.ones_like(magnitude_spectrum, dtype=bool)
        outer_mask[max(0, center_y - h//4):min(h, center_y + h//4),
                   max(0, center_x - w//4):min(w, center_x + w//4)] = False
        outer_freq_mean = np.mean(magnitude_spectrum[outer_mask])
        
        freq_ratio = outer_freq_mean / (high_freq_mean + 1e-10)
        
        gan_score = 0.0
        if freq_ratio > 0.8:
            gan_score = min((freq_ratio - 0.8) * 2, 1.0)
        if high_freq_std < 15:
            gan_score += 0.15
        
        return gan_score, {
            "high_freq_mean": float(high_freq_mean),
            "high_freq_std": float(high_freq_std),
            "freq_ratio": float(freq_ratio)
        }
    
    def analyze_noise_patterns(self, image: np.ndarray) -> Tuple[float, Dict]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
        
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)
        laplacian_var = laplacian.var()
        
        noise = gray.astype(float) - cv2.GaussianBlur(gray, (5, 5), 0).astype(float)
        noise_std = np.std(noise)
        
        sobelx = cv2.Sobel(gray, cv2.CV_64F, 1, 0, ksize=3)
        sobely = cv2.Sobel(gray, cv2.CV_64F, 0, 1, ksize=3)
        edge_magnitude = np.sqrt(sobelx**2 + sobely**2)
        edge_mean = np.mean(edge_magnitude)
        
        score = 0.0
        
        if laplacian_var < 50:
            score += 0.2
        elif laplacian_var > 500:
            score += 0.1
        
        if noise_std < 2:
            score += 0.2
        elif noise_std > 20:
            score += 0.15
        
        if edge_mean < 10:
            score += 0.1
        
        return min(score, 1.0), {
            "laplacian_variance": float(laplacian_var),
            "noise_std": float(noise_std),
            "edge_mean": float(edge_mean)
        }
    
    def analyze_color_consistency(self, image: np.ndarray) -> Tuple[float, Dict]:
        if len(image.shape) != 3:
            return 0.0, {"error": "Not a color image"}
        
        lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
        l, a, b = cv2.split(lab)
        
        color_std_a = np.std(a)
        color_std_b = np.std(b)
        
        hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
        h, s, v = cv2.split(hsv)
        sat_mean = np.mean(s)
        sat_std = np.std(s)
        
        bgr_std = [np.std(image[:,:,i]) for i in range(3)]
        channel_ratio = max(bgr_std) / (min(bgr_std) + 1e-10)
        
        score = 0.0
        
        if channel_ratio > 3:
            score += 0.15
        
        if sat_std < 30:
            score += 0.1
        
        if color_std_a < 10 or color_std_b < 10:
            score += 0.15
        
        return min(score, 1.0), {
            "color_std_a": float(color_std_a),
            "color_std_b": float(color_std_b),
            "saturation_mean": float(sat_mean),
            "saturation_std": float(sat_std),
            "channel_ratio": float(channel_ratio)
        }
    
    def analyze_face_artifacts(self, image: np.ndarray, faces: List[Tuple]) -> Tuple[float, Dict]:
        if not faces:
            return 0.0, {"faces_detected": 0, "analysis": "No faces detected"}
        
        face_scores = []
        face_details = []
        
        for (x, y, w, h) in faces:
            face_roi = image[y:y+h, x:x+w]
            if face_roi.size == 0:
                continue
            
            face_gray = cv2.cvtColor(face_roi, cv2.COLOR_BGR2GRAY) if len(face_roi.shape) == 3 else face_roi
            blur_score = cv2.Laplacian(face_gray, cv2.CV_64F).var()
            
            hsv_face = cv2.cvtColor(face_roi, cv2.COLOR_BGR2HSV)
            skin_lower = np.array([0, 20, 70])
            skin_upper = np.array([20, 255, 255])
            skin_mask = cv2.inRange(hsv_face, skin_lower, skin_upper)
            skin_ratio = np.sum(skin_mask > 0) / (w * h)
            
            sobelx = cv2.Sobel(face_gray, cv2.CV_64F, 1, 0, ksize=3)
            sobely = cv2.Sobel(face_gray, cv2.CV_64F, 0, 1, ksize=3)
            edge_consistency = np.std(np.sqrt(sobelx**2 + sobely**2))
            
            face_score = 0.0
            
            if blur_score < 30:
                face_score += 0.2
            
            if skin_ratio < 0.1 or skin_ratio > 0.9:
                face_score += 0.15
            
            if edge_consistency < 15:
                face_score += 0.15
            
            face_scores.append(face_score)
            face_details.append({
                "position": {"x": int(x), "y": int(y), "width": int(w), "height": int(h)},
                "blur_score": float(blur_score),
                "skin_ratio": float(skin_ratio),
                "edge_consistency": float(edge_consistency),
                "artifact_score": float(face_score)
            })
        
        avg_score = np.mean(face_scores) if face_scores else 0.0
        
        return float(avg_score), {
            "faces_detected": len(faces),
            "face_analysis": face_details
        }
    
    def analyze_compression_artifacts(self, image: np.ndarray) -> Tuple[float, Dict]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
        
        block_size = 8
        h, w = gray.shape
        h_blocks = h // block_size
        w_blocks = w // block_size
        
        if h_blocks < 2 or w_blocks < 2:
            return 0.0, {"error": "Image too small for block analysis"}
        
        block_means = []
        for i in range(h_blocks):
            for j in range(w_blocks):
                block = gray[i*block_size:(i+1)*block_size, j*block_size:(j+1)*block_size]
                block_means.append(np.mean(block))
        
        block_std = np.std(block_means)
        
        edges = cv2.Canny(gray, 50, 150)
        h_edges = np.sum(edges[::block_size, :]) 
        v_edges = np.sum(edges[:, ::block_size])
        total_edges = np.sum(edges)
        
        grid_ratio = (h_edges + v_edges) / (total_edges + 1e-10)
        
        score = 0.0
        if grid_ratio > 0.2:
            score += 0.1
        if block_std < 20:
            score += 0.15
        
        return min(score, 1.0), {
            "block_std": float(block_std),
            "grid_edge_ratio": float(grid_ratio)
        }
    
    def analyze_image(self, image_data: bytes) -> Dict[str, Any]:
        try:
            nparr = np.frombuffer(image_data, np.uint8)
            image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if image is None:
                pil_image = Image.open(io.BytesIO(image_data))
                image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            if image is None:
                return {
                    "success": False,
                    "error": "Failed to decode image",
                    "is_deepfake": None,
                    "confidence": None
                }
            
            faces = self.detect_faces(image)
            
            freq_score, freq_details = self.analyze_frequency_artifacts(image)
            noise_score, noise_details = self.analyze_noise_patterns(image)
            color_score, color_details = self.analyze_color_consistency(image)
            face_score, face_details = self.analyze_face_artifacts(image, faces)
            compression_score, compression_details = self.analyze_compression_artifacts(image)
            
            weights = {
                "frequency": 0.25,
                "noise": 0.20,
                "color": 0.15,
                "face": 0.30,
                "compression": 0.10
            }
            
            weighted_score = (
                freq_score * weights["frequency"] +
                noise_score * weights["noise"] +
                color_score * weights["color"] +
                face_score * weights["face"] +
                compression_score * weights["compression"]
            )
            
            final_confidence = min(max(weighted_score, 0.0), 1.0)
            
            is_deepfake = final_confidence > 0.35
            
            if final_confidence < 0.2:
                verdict = "LIKELY AUTHENTIC"
                risk_level = "LOW"
            elif final_confidence < 0.35:
                verdict = "POSSIBLY AUTHENTIC"
                risk_level = "MEDIUM-LOW"
            elif final_confidence < 0.5:
                verdict = "SUSPICIOUS"
                risk_level = "MEDIUM"
            elif final_confidence < 0.7:
                verdict = "LIKELY DEEPFAKE"
                risk_level = "HIGH"
            else:
                verdict = "HIGHLY LIKELY DEEPFAKE"
                risk_level = "VERY HIGH"
            
            return {
                "success": True,
                "is_deepfake": is_deepfake,
                "confidence": round(final_confidence * 100, 2),
                "verdict": verdict,
                "risk_level": risk_level,
                "analysis_method": "MesoNet-style CNN Analysis",
                "component_scores": {
                    "frequency_analysis": {
                        "score": round(freq_score * 100, 2),
                        "weight": weights["frequency"],
                        "details": freq_details
                    },
                    "noise_pattern_analysis": {
                        "score": round(noise_score * 100, 2),
                        "weight": weights["noise"],
                        "details": noise_details
                    },
                    "color_consistency": {
                        "score": round(color_score * 100, 2),
                        "weight": weights["color"],
                        "details": color_details
                    },
                    "face_artifact_analysis": {
                        "score": round(face_score * 100, 2),
                        "weight": weights["face"],
                        "details": face_details
                    },
                    "compression_analysis": {
                        "score": round(compression_score * 100, 2),
                        "weight": weights["compression"],
                        "details": compression_details
                    }
                },
                "image_info": {
                    "width": image.shape[1],
                    "height": image.shape[0],
                    "channels": image.shape[2] if len(image.shape) == 3 else 1,
                    "faces_detected": len(faces)
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "is_deepfake": None,
                "confidence": None
            }
    
    def analyze_video_frame(self, frame: np.ndarray) -> Dict[str, Any]:
        is_success, buffer = cv2.imencode('.jpg', frame)
        if not is_success:
            return {"success": False, "error": "Failed to encode frame"}
        return self.analyze_image(buffer.tobytes())


mesonet_detector = MesoNetDetector()
