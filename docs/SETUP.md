# Setup

## Prerequisites

- Python 3.10 or newer
- Node.js 18 or newer and npm

Run the backend and frontend in separate terminals from the repository root.

## Backend Setup

Create and activate a virtual environment.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS or Linux:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
uvicorn backend.app:app --reload
```

The API is available at `http://localhost:8000`; interactive documentation is at `http://localhost:8000/docs`.

## Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Vite prints the local dashboard URL after startup. Use `npm run build` to verify a production bundle.

## Sample Data

Synthetic source samples and a labeled multi-stage scenario are in `datasets/`. They are fixtures for development, not a benchmark dataset.