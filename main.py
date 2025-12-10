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
    import os
    
    modules_status = {
        "h8mail": {
            "installed": bool(os.listdir("Modules/Darkweb Scan/h8mail")) if os.path.exists("Modules/Darkweb Scan/h8mail") else False,
            "path": "Modules/Darkweb Scan/h8mail"
        },
        "TorCrawl": {
            "installed": bool(os.listdir("Modules/Darkweb Scan/TorCrawl.py")) if os.path.exists("Modules/Darkweb Scan/TorCrawl.py") else False,
            "path": "Modules/Darkweb Scan/TorCrawl.py"
        },
        "WhatBreach": {
            "installed": bool(os.listdir("Modules/Darkweb Scan/WhatBreach")) if os.path.exists("Modules/Darkweb Scan/WhatBreach") else False,
            "path": "Modules/Darkweb Scan/WhatBreach"
        },
        "FACTOR": {
            "installed": bool(os.listdir("Modules/deepfake scan/FACTOR")) if os.path.exists("Modules/deepfake scan/FACTOR") else False,
            "path": "Modules/deepfake scan/FACTOR"
        }
    }
    
    return JSONResponse(content={"status": "success", "modules": modules_status})
