import cv2
import numpy as np
from PIL import Image
import io
from typing import Dict, Any, Tuple, List
import os

def convert_numpy_types(obj):
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(v) for v in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj

MESONET_MODEL_AVAILABLE = False
meso4_classifier = None
meso_inception_classifier = None

try:
    import tensorflow as tf
    tf.get_logger().setLevel('ERROR')
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    
    from classifiers import Meso4, MesoInception4
    
    base_path = os.path.dirname(os.path.abspath(__file__))
    weights_path_meso4 = os.path.join(base_path, 'weights', 'Meso4_DF.h5')
    weights_path_inception = os.path.join(base_path, 'weights', 'MesoInception_DF.h5')
    
    if os.path.exists(weights_path_meso4):
        meso4_classifier = Meso4()
        meso4_classifier.load(weights_path_meso4)
        MESONET_MODEL_AVAILABLE = True
        print("MesoNet Meso4 model loaded successfully")
    
    if os.path.exists(weights_path_inception):
        meso_inception_classifier = MesoInception4()
        meso_inception_classifier.load(weights_path_inception)
        print("MesoNet MesoInception4 model loaded successfully")
        
except ImportError as e:
    print(f"TensorFlow/Keras not available: {e}")
except Exception as e:
    print(f"Error loading MesoNet models: {e}")

IMGWIDTH = 256

class MesoNetDetector:
    def __init__(self):
        self.face_cascade = None
        self._load_face_detector()
        self.meso4 = meso4_classifier
        self.meso_inception = meso_inception_classifier
        self.model_available = MESONET_MODEL_AVAILABLE
    
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
    
    def preprocess_image(self, image: np.ndarray) -> np.ndarray:
        if image.shape[0] != IMGWIDTH or image.shape[1] != IMGWIDTH:
            image = cv2.resize(image, (IMGWIDTH, IMGWIDTH))
        
        if len(image.shape) == 2:
            image = cv2.cvtColor(image, cv2.COLOR_GRAY2RGB)
        elif image.shape[2] == 4:
            image = cv2.cvtColor(image, cv2.COLOR_BGRA2RGB)
        elif image.shape[2] == 3:
            image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        
        image = image.astype(np.float32) / 255.0
        image = np.expand_dims(image, axis=0)
        
        return image
    
    def preprocess_face(self, image: np.ndarray, face_bbox: Tuple[int, int, int, int]) -> np.ndarray:
        x, y, w, h = face_bbox
        
        margin = int(0.3 * max(w, h))
        x1 = max(0, x - margin)
        y1 = max(0, y - margin)
        x2 = min(image.shape[1], x + w + margin)
        y2 = min(image.shape[0], y + h + margin)
        
        face_crop = image[y1:y2, x1:x2]
        return self.preprocess_image(face_crop)
    
    def predict_with_mesonet(self, image: np.ndarray, faces: List[Tuple]) -> Tuple[float, Dict]:
        if not self.model_available or self.meso4 is None:
            return 0.0, {"error": "MesoNet model not available"}
        
        predictions = []
        face_predictions = []
        
        if faces:
            for face_bbox in faces:
                try:
                    face_input = self.preprocess_face(image, face_bbox)
                    
                    meso4_pred = float(self.meso4.predict(face_input)[0][0])
                    predictions.append(meso4_pred)
                    
                    inception_pred = None
                    if self.meso_inception is not None:
                        inception_pred = float(self.meso_inception.predict(face_input)[0][0])
                        predictions.append(inception_pred)
                    
                    face_predictions.append({
                        "face_bbox": {"x": int(face_bbox[0]), "y": int(face_bbox[1]), 
                                      "width": int(face_bbox[2]), "height": int(face_bbox[3])},
                        "meso4_score": meso4_pred,
                        "meso_inception_score": inception_pred
                    })
                except Exception as e:
                    face_predictions.append({
                        "face_bbox": {"x": int(face_bbox[0]), "y": int(face_bbox[1]),
                                      "width": int(face_bbox[2]), "height": int(face_bbox[3])},
                        "error": str(e)
                    })
        else:
            try:
                full_input = self.preprocess_image(image)
                meso4_pred = float(self.meso4.predict(full_input)[0][0])
                predictions.append(meso4_pred)
                
                if self.meso_inception is not None:
                    inception_pred = float(self.meso_inception.predict(full_input)[0][0])
                    predictions.append(inception_pred)
            except Exception as e:
                return 0.0, {"error": str(e)}
        
        if predictions:
            fake_score = 1.0 - np.mean(predictions)
        else:
            fake_score = 0.0
        
        return fake_score, {
            "faces_analyzed": len(faces) if faces else 1,
            "face_predictions": face_predictions,
            "average_authenticity_score": float(np.mean(predictions)) if predictions else 0.0,
            "model_used": "MesoNet (Meso4 + MesoInception4)"
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
            
            if self.model_available and self.meso4 is not None:
                mesonet_score, mesonet_details = self.predict_with_mesonet(image, faces)
                
                confidence = mesonet_score
                is_deepfake = confidence > 0.5
                
                if confidence < 0.3:
                    verdict = "LIKELY AUTHENTIC"
                    risk_level = "LOW"
                elif confidence < 0.5:
                    verdict = "POSSIBLY AUTHENTIC"
                    risk_level = "MEDIUM-LOW"
                elif confidence < 0.7:
                    verdict = "SUSPICIOUS - POSSIBLE DEEPFAKE"
                    risk_level = "MEDIUM-HIGH"
                elif confidence < 0.85:
                    verdict = "LIKELY DEEPFAKE"
                    risk_level = "HIGH"
                else:
                    verdict = "HIGHLY LIKELY DEEPFAKE"
                    risk_level = "VERY HIGH"
                
                result = {
                    "success": True,
                    "is_deepfake": bool(is_deepfake),
                    "confidence": float(round(confidence * 100, 2)),
                    "verdict": verdict,
                    "risk_level": risk_level,
                    "analysis_method": "MesoNet Pre-trained Model (Meso4 + MesoInception4)",
                    "mesonet_analysis": mesonet_details,
                    "image_info": {
                        "width": int(image.shape[1]),
                        "height": int(image.shape[0]),
                        "channels": int(image.shape[2]) if len(image.shape) == 3 else 1,
                        "faces_detected": int(len(faces))
                    }
                }
                return convert_numpy_types(result)
            else:
                return {
                    "success": False,
                    "error": "MesoNet pre-trained model not available",
                    "is_deepfake": None,
                    "confidence": None
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
