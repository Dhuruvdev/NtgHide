# Censored Scanner - Security Analysis Platform

## Overview
A FastAPI-based security scanning platform with a dark, censored theme. The platform integrates multiple security analysis modules for:
1. **Darkweb Data Breach Scanning** - Checks if user data appears in breach databases
2. **Deepfake Detection** - Analyzes images/videos for AI-generated manipulation

## Project Structure
```
├── main.py                    # FastAPI application with API endpoints
├── services/
│   ├── darkweb_scanner.py    # Service layer for darkweb scan modules
│   └── deepfake_detector.py  # Service layer for deepfake detection
├── templates/
│   └── index.html            # Main page with dark theme and search interfaces
├── static/
│   ├── css/style.css         # CSS styles (embedded in HTML)
│   └── images/
│       └── loading.gif       # Loading animation
├── Modules/
│   ├── Darkweb Scan/
│   │   ├── h8mail/           # Email breach hunter (needs installation)
│   │   ├── TorCrawl.py/      # Tor network crawler (needs installation)
│   │   └── WhatBreach/       # Breach database checker (needs installation)
│   └── deepfake scan/
│       └── FACTOR/           # Deepfake detection (needs installation)
```

## API Endpoints

### GET `/`
Main page with search interfaces for both scanning services.

### POST `/api/darkweb/scan`
Scans a query (email) across all three darkweb modules in parallel.
- Request: `{"query": "email@example.com"}`
- Response: Combined results from h8mail, TorCrawl, and WhatBreach

### POST `/api/deepfake/upload`
Uploads and analyzes a file for deepfake detection.
- Request: Multipart form with `file` field
- Response: FACTOR analysis results

### GET `/api/status`
Returns installation status of all modules.

## Module Installation

The module folders are currently empty. To enable full functionality:

### h8mail (Email Breach Hunter)
```bash
cd "Modules/Darkweb Scan/h8mail"
git clone https://github.com/khast3x/h8mail.git .
pip install -r requirements.txt
```

### TorCrawl (Darkweb Crawler)
```bash
cd "Modules/Darkweb Scan/TorCrawl.py"
git clone https://github.com/MikeMeliz/TorCrawl.py.git .
pip install -r requirements.txt
# Requires Tor service running
```

### WhatBreach (Breach Database)
```bash
cd "Modules/Darkweb Scan/WhatBreach"
git clone https://github.com/Ekultek/WhatBreach.git .
pip install -r requirements.txt
```

### FACTOR (Deepfake Detection)
```bash
cd "Modules/deepfake scan/FACTOR"
git clone https://github.com/talreiss/FACTOR.git .
pip install -r requirements.txt
```

## Running the Application
```bash
uvicorn main:app --host 0.0.0.0 --port 5000 --reload
```

## User Preferences
- Dark theme with censored/classified aesthetic
- Loading GIF from attached_assets for loading screen
- FastAPI framework for backend

## Recent Changes
- 2025-12-10: Initial setup with FastAPI, dark theme, search interfaces
- 2025-12-10: Added service layers for darkweb scanning and deepfake detection
- 2025-12-10: Created API endpoints connecting frontend to services
- 2025-12-10: All three darkweb modules run in parallel on single query
