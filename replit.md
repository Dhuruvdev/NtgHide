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

## Module Integration

### Check My Data (Darkweb Scanning)
Uses WhatBreach and SpiderFoot modules directly:
- **WhatBreach/EmailRep**: Queries EmailRep.io for email reputation and associated profiles
- **WhatBreach/Dehashed**: Checks Dehashed for breach database entries
- **SpiderFoot/LeakDB**: Checks against known major breaches (LinkedIn, Facebook, Yahoo, etc.)
- **SpiderFoot/Ahmia**: Searches dark web index via Ahmia.fi

No external API keys required - uses free public sources.

### DeepFake-Image-Detection (Deepfake Detection)
Multi-layer image analysis system that analyzes images for deepfake indicators:
- Supports image formats: jpg, jpeg, png, bmp, gif, webp
- Uses 9 analysis methods including convolutional feature extraction, ELA, frequency domain analysis
- Returns confidence score, verdict, and detailed analysis breakdown

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
- 2025-12-10: Enhanced threat classification system (CRITICAL, HIGH, MEDIUM, LOW)
- 2025-12-10: Added categorized findings display with recommendations
- 2025-12-10: Added GIF loading animations during scan operations
- 2025-12-10: Rewrote darkweb scanner to use WhatBreach and SpiderFoot modules directly (no HIBP dependency)
- 2025-12-10: Created FACTOR detect.py script for deepfake detection
- 2025-12-10: Integrated WhatBreach hooks (EmailRepHook, DehashedHook) directly
- 2025-12-10: Added SpiderFoot LeakDB and Ahmia dark web scanning
- 2025-12-10: Created missing WhatBreach lib folder (settings.py, formatter.py, cmd.py) for proper module imports
- 2025-12-10: Fixed import paths for WhatBreach and SpiderFoot direct module access
- 2025-12-10: Updated /api/status endpoint to show module integration status
