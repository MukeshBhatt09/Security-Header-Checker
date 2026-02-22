from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware

import httpx
import os
from dotenv import load_dotenv
load_dotenv()

app = FastAPI()
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
async def serve_home():
    return FileResponse("index.html")

# Allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: HttpUrl

REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy"
]

@app.post("/analyze")
async def analyze(data: URLRequest):

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(str(data.url))
        headers = {k.lower(): v for k, v in response.headers.items()}

    analysis = {}

    for header in REQUIRED_HEADERS:
        if header in headers:
            analysis[header] = "PRESENT"
        else:
            analysis[header] = "MISSING"

    # LLM integration: call Groq Llama-3 using the API key from .env
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

    if not GROQ_API_KEY:
        ai_analysis = "GROQ_API_KEY not set. Add it to .env"
    else:
        prompt = (
            "You are a security assistant. Given the following HTTP response headers for a website, "
            "explain which security headers are missing and provide concise remediation steps.\n\n"
            f"Headers present: {', '.join([k for k, v in analysis.items() if v == 'PRESENT'])}\n"
            f"Headers missing: {', '.join([k for k, v in analysis.items() if v == 'MISSING'])}\n\n"
            "Return a short, bullet-style summary."
        )

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {GROQ_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "llama-3.1-8b-instant",
                        "messages": [
                            {"role": "system", "content": "You are a helpful security assistant."},
                            {"role": "user", "content": prompt},
                        ],
                        "max_tokens": 300,
                        "temperature": 0.2,
                    },
                )

                status = resp.status_code
                text = resp.text
                try:
                    j = resp.json()
                except Exception:
                    j = None

                if status != 200:
                    err_msg = None
                    if j and isinstance(j, dict) and j.get("error"):
                        err_msg = j["error"].get("message")
                    ai_analysis = f"Groq API error {status}: {err_msg or text[:500]}"
                else:
                    choices = (j or {}).get("choices", [])
                    if choices and len(choices) > 0:
                        raw_content = choices[0].get("message", {}).get("content", "") or ""
                        if not raw_content:
                            ai_analysis = "Groq returned empty content in choices."
                        else:
                            import re
                            md = raw_content.strip()
                            # Remove duplicate main header if present
                            md = re.sub(r"^\s*\*+AI Security Header Analysis\*+", "", md)
                            # Remove stray asterisks and single quotes
                            md = re.sub(r"\*+", "", md)
                            md = md.replace("'", "")
                            # Section headers: bold and on their own lines, with blank lines before
                            md = re.sub(r"Missing Security Header:?", "\n**Missing Security Header:**\n", md)
                            md = re.sub(r"Header Name:?", "\n**Header Name:**\n", md)
                            md = re.sub(r"Purpose:?", "\n**Purpose:**\n", md)
                            md = re.sub(r"Description:?", "\n**Description:**\n", md)
                            md = re.sub(r"Remediation Steps:?", "\n**Remediation Steps:**\n", md)
                            # Bullet points: - at start of line, with blank lines between
                            md = re.sub(r"\n\s*\+", "\n- ", md)
                            md = re.sub(r"\+", "\n- ", md)
                            md = re.sub(r"\n- ", "\n\n- ", md)
                            # Code blocks: triple backticks for examples, with blank lines before/after
                            md = re.sub(r"``([^`]+)``", r"\n\n```\1```\n\n", md)
                            md = re.sub(r"Example: ([^\n]+)", r"\n**Example:**\n\n```\1```\n", md)
                            # Clean up extra whitespace
                            md = re.sub(r"\n{3,}", "\n\n", md)
                            ai_analysis = f"**AI Security Header Analysis**\n\n{md.strip()}"
                    else:
                        ai_analysis = f"No choices in Groq response. Raw: {text[:500]}"
        except Exception as e:
            ai_analysis = f"Error calling Groq API: {e}"

    return {
        "analysis": analysis,
        "ai_analysis": ai_analysis
    }
