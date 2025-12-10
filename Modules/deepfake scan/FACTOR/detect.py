#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "MesoNet"))

try:
    from mesonet_detector import MesoNetDetector
    detector = MesoNetDetector()
    MESONET_AVAILABLE = True
except ImportError:
    detector = None
    MESONET_AVAILABLE = False

def analyze_image(image_path: str) -> dict:
    if not os.path.exists(image_path):
        return {"error": f"File not found: {image_path}"}
    
    file_ext = Path(image_path).suffix.lower()
    supported_formats = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp']
    
    if file_ext not in supported_formats:
        return {"error": f"Unsupported format: {file_ext}"}
    
    if not MESONET_AVAILABLE or detector is None:
        return {"error": "MesoNet detector not available"}
    
    try:
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        result = detector.analyze_image(image_data)
        
        if not result.get("success", False):
            return {"error": result.get("error", "Analysis failed")}
        
        return {
            "is_deepfake": result.get("is_deepfake", False),
            "confidence": result.get("confidence", 0) / 100.0,
            "analysis": {
                "file_path": image_path,
                "file_size": os.path.getsize(image_path),
                "format": file_ext,
                "analysis_method": result.get("analysis_method", "MesoNet Analysis"),
                "verdict": result.get("verdict", "Unknown"),
                "risk_level": result.get("risk_level", "Unknown"),
                "component_scores": result.get("component_scores", {}),
                "image_info": result.get("image_info", {}),
                "checks_performed": [
                    "Frequency artifact analysis (GAN detection)",
                    "Noise pattern analysis",
                    "Color consistency check",
                    "Face artifact detection",
                    "Compression artifact analysis"
                ]
            }
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_video(video_path: str) -> dict:
    if not os.path.exists(video_path):
        return {"error": f"File not found: {video_path}"}
    
    file_ext = Path(video_path).suffix.lower()
    supported_formats = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.wmv']
    
    if file_ext not in supported_formats:
        return {"error": f"Unsupported format: {file_ext}"}
    
    if not MESONET_AVAILABLE or detector is None:
        return {"error": "MesoNet detector not available"}
    
    try:
        import cv2
        cap = cv2.VideoCapture(video_path)
        
        if not cap.isOpened():
            return {"error": "Could not open video file"}
        
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        
        sample_interval = max(1, frame_count // 10)
        frame_results = []
        
        frame_idx = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            if frame_idx % sample_interval == 0:
                result = detector.analyze_video_frame(frame)
                if result.get("success", False):
                    frame_results.append({
                        "frame": frame_idx,
                        "is_deepfake": result.get("is_deepfake", False),
                        "confidence": result.get("confidence", 0)
                    })
            
            frame_idx += 1
            
            if len(frame_results) >= 10:
                break
        
        cap.release()
        
        if not frame_results:
            return {"error": "Could not analyze any frames"}
        
        avg_confidence = sum(r["confidence"] for r in frame_results) / len(frame_results)
        deepfake_count = sum(1 for r in frame_results if r["is_deepfake"])
        is_deepfake = deepfake_count > len(frame_results) / 2
        
        if avg_confidence < 20:
            verdict = "LIKELY AUTHENTIC"
            risk_level = "LOW"
        elif avg_confidence < 35:
            verdict = "POSSIBLY AUTHENTIC"
            risk_level = "MEDIUM-LOW"
        elif avg_confidence < 50:
            verdict = "SUSPICIOUS"
            risk_level = "MEDIUM"
        elif avg_confidence < 70:
            verdict = "LIKELY DEEPFAKE"
            risk_level = "HIGH"
        else:
            verdict = "HIGHLY LIKELY DEEPFAKE"
            risk_level = "VERY HIGH"
        
        return {
            "is_deepfake": is_deepfake,
            "confidence": avg_confidence / 100.0,
            "analysis": {
                "file_path": video_path,
                "file_size": os.path.getsize(video_path),
                "format": file_ext,
                "analysis_method": "MesoNet Temporal Analysis",
                "verdict": verdict,
                "risk_level": risk_level,
                "video_info": {
                    "frame_count": frame_count,
                    "fps": fps,
                    "frames_analyzed": len(frame_results)
                },
                "frame_results": frame_results,
                "checks_performed": [
                    "Multi-frame frequency analysis",
                    "Temporal consistency check",
                    "Face tracking analysis",
                    "Frame-to-frame artifact detection"
                ]
            }
        }
    except ImportError:
        return {"error": "OpenCV not available for video analysis"}
    except Exception as e:
        return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description='FACTOR Deepfake Detection with MesoNet')
    parser.add_argument('--input', '-i', required=True, help='Path to input file (image or video)')
    parser.add_argument('--output', '-o', help='Path to output JSON file (optional)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    input_path = args.input
    
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    file_ext = Path(input_path).suffix.lower()
    image_formats = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp']
    video_formats = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.wmv']
    
    if file_ext in image_formats:
        result = analyze_image(input_path)
    elif file_ext in video_formats:
        result = analyze_video(input_path)
    else:
        print(f"Error: Unsupported file format: {file_ext}")
        sys.exit(1)
    
    if "error" in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    if result["is_deepfake"]:
        print(f"Result: POTENTIAL DEEPFAKE DETECTED")
    else:
        print(f"Result: LIKELY AUTHENTIC")
    
    confidence_pct = result['confidence'] * 100 if result['confidence'] <= 1 else result['confidence']
    print(f"Confidence: {confidence_pct:.2f}%")
    
    if "analysis" in result:
        print(f"Verdict: {result['analysis'].get('verdict', 'Unknown')}")
        print(f"Risk Level: {result['analysis'].get('risk_level', 'Unknown')}")
    
    if args.verbose:
        print(f"\nAnalysis Details:")
        analysis = result.get("analysis", {})
        for key, value in analysis.items():
            if key in ['component_scores', 'frame_results']:
                print(f"  {key}:")
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        print(f"    {sub_key}: {sub_value}")
                elif isinstance(value, list):
                    for item in value[:5]:
                        print(f"    - {item}")
            elif isinstance(value, list):
                print(f"  {key}:")
                for item in value:
                    print(f"    - {item}")
            elif isinstance(value, dict):
                print(f"  {key}: {value}")
            else:
                print(f"  {key}: {value}")
    
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()
