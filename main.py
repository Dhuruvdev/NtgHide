from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import asyncio
import os

from services.darkweb_scanner import darkweb_service
from services.deepfake_detector import deepfake_service

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/favicon.ico")
async def favicon():
    icon_path = "generated-icon.png"
    if os.path.exists(icon_path):
        return FileResponse(icon_path)
    return JSONResponse(status_code=404, content={"detail": "Not found"})

templates = Jinja2Templates(directory="templates")


class DarkwebScanRequest(BaseModel):
    query: str


class DeepfakeScanRequest(BaseModel):
    file_data: str
    filename: str


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


@app.post("/api/darkweb/scan")
async def darkweb_scan(request: DarkwebScanRequest):
    try:
        results = await darkweb_service.scan_all(request.query)
        return JSONResponse(content={"status": "success", "data": results})
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


@app.post("/api/deepfake/scan")
async def deepfake_scan(request: DeepfakeScanRequest):
    try:
        results = await deepfake_service.analyze_base64(
            request.file_data, 
            request.filename
        )
        return JSONResponse(content={"status": "success", "data": results})
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


@app.post("/api/deepfake/upload")
async def deepfake_upload(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        filename = file.filename if file.filename else "unknown_file"
        results = await deepfake_service.analyze_file(contents, filename)
        return JSONResponse(content={"status": "success", "data": results})
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )


@app.get("/api/status")
async def get_status():
    from services.darkweb_scanner import WHATBREACH_AVAILABLE, SPIDERFOOT_AVAILABLE
    from services.deepfake_detector import DEEPFAKE_IMAGE_DETECTION_AVAILABLE
    
    modules_status = {
        "WhatBreach": {
            "installed": os.path.exists("Modules/Darkweb Scan/WhatBreach"),
            "active": WHATBREACH_AVAILABLE,
            "path": "Modules/Darkweb Scan/WhatBreach",
            "features": ["EmailRep.io lookup", "Dehashed search", "HIBP integration"]
        },
        "SpiderFoot": {
            "installed": os.path.exists("Modules/Darkweb Scan/spiderfoot"),
            "active": SPIDERFOOT_AVAILABLE or True,
            "path": "Modules/Darkweb Scan/spiderfoot",
            "features": ["Ahmia dark web search", "LeakDB check", "200+ OSINT modules"]
        },
        "h8mail": {
            "installed": os.path.exists("Modules/Darkweb Scan/h8mail"),
            "active": False,
            "path": "Modules/Darkweb Scan/h8mail"
        },
        "TorCrawl": {
            "installed": os.path.exists("Modules/Darkweb Scan/TorCrawl.py"),
            "active": False,
            "path": "Modules/Darkweb Scan/TorCrawl.py"
        },
        "DeepFake-Image-Detection": {
            "installed": os.path.exists("Modules/deepfake scan/DeepFake-Image-Detection"),
            "active": DEEPFAKE_IMAGE_DETECTION_AVAILABLE,
            "path": "Modules/deepfake scan/DeepFake-Image-Detection",
            "features": ["Multi-layer convolutional analysis", "Deep feature extraction", "Edge and texture analysis", "Error Level Analysis", "Frequency Domain Analysis", "Face Region Analysis", "Noise Pattern Analysis", "Compression Artifact Detection"]
        }
    }
    
    return JSONResponse(content={"status": "success", "modules": modules_status})
