# Incident triage agent (ga5-incident-agent/v2)

## Deploy on Render
1. Push this folder to a GitHub repo (`main.py`, `requirements.txt`, `README.md`; `test_local.py` is optional).
2. Render -> New -> Web Service -> pick the repo.
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1`
   - Keep it at ONE worker (per-run locks live in process memory).
3. Environment variables:
   - `GEMINI_API_KEY` = key from Google AI Studio
   - `GEMINI_MODEL` = `gemini-3.5-flash-lite` (copy the exact id shown in AI Studio)
   - `DATABASE_URL` = Postgres URL from a free Neon database (recommended; Render's free disk is wiped on restart/redeploy)
4. Submit `https://<your-service>.onrender.com` as the base URL (no trailing path, query or fragment).
5. Free Render services sleep after idle time. Open the URL once right before each Check so the first request isn't slow.

## Test locally (no API key needed)
    pip install -r requirements.txt
    python test_local.py

To run for real locally: `GEMINI_API_KEY=... uvicorn main:app --port 8000`
