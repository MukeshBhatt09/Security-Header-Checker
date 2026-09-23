from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl
from fastapi.middleware.cors import CORSMiddleware

import httpx
import os
import re
import time
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


# Additional headers checked in the extended analysis.
# These do NOT replace your original REQUIRED_HEADERS.
ADDITIONAL_HEADERS = [
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "cache-control",
    "pragma",
    "server",
    "x-powered-by",
    "access-control-allow-origin"
]


HEADER_METADATA = {
    "content-security-policy": {
        "category": "Browser Security",
        "severity": "High",
        "recommendation": "Define a restrictive Content-Security-Policy."
    },

    "strict-transport-security": {
        "category": "Transport Security",
        "severity": "High",
        "recommendation": "Use HSTS with an appropriate max-age."
    },

    "x-frame-options": {
        "category": "Clickjacking",
        "severity": "Medium",
        "recommendation": "Use DENY or SAMEORIGIN where appropriate."
    },

    "x-content-type-options": {
        "category": "Browser Security",
        "severity": "Medium",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },

    "referrer-policy": {
        "category": "Privacy",
        "severity": "Medium",
        "recommendation": "Consider strict-origin-when-cross-origin."
    },

    "permissions-policy": {
        "category": "Browser Privacy",
        "severity": "Low",
        "recommendation": "Restrict browser features the application does not need."
    },

    "cross-origin-opener-policy": {
        "category": "Cross-Origin",
        "severity": "Low",
        "recommendation": "Consider same-origin where appropriate."
    },

    "cross-origin-resource-policy": {
        "category": "Cross-Origin",
        "severity": "Low",
        "recommendation": "Consider same-origin or same-site where appropriate."
    },

    "cross-origin-embedder-policy": {
        "category": "Cross-Origin",
        "severity": "Low",
        "recommendation": "Consider require-corp where appropriate."
    },

    "cache-control": {
        "category": "Caching",
        "severity": "Medium",
        "recommendation": "Use appropriate cache directives."
    }
}


def check_header_quality(header, value):
    """
    Checks whether a present security header appears to have
    a weak configuration.

    Your original PRESENT/MISSING analysis remains unchanged.
    """

    value = (value or "").strip()

    if not value:
        return "WEAK"

    if header == "content-security-policy":

        lowered = value.lower()

        weak_patterns = [
            "default-src *",
            "script-src *",
            "script-src 'unsafe-inline'",
            "script-src 'unsafe-eval'",
            "object-src *"
        ]

        if any(pattern in lowered for pattern in weak_patterns):
            return "WEAK"

    elif header == "strict-transport-security":

        match = re.search(
            r"max-age\s*=\s*(\d+)",
            value,
            re.IGNORECASE
        )

        if not match:
            return "WEAK"

        if int(match.group(1)) < 31536000:
            return "WEAK"

    elif header == "x-frame-options":

        if value.upper() not in ["DENY", "SAMEORIGIN"]:
            return "WEAK"

    elif header == "x-content-type-options":

        if value.lower() != "nosniff":
            return "WEAK"

    elif header == "referrer-policy":

        if value.lower() in [
            "unsafe-url",
            "no-referrer-when-downgrade"
        ]:
            return "WEAK"

    elif header == "permissions-policy":

        if value.strip() == "*":
            return "WEAK"

    return "PRESENT"


def build_header_details(headers):

    details = {}

    for header in REQUIRED_HEADERS + ADDITIONAL_HEADERS:

        value = headers.get(header)

        if value is None:
            status = "MISSING"
        else:
            status = check_header_quality(
                header,
                value
            )

        metadata = HEADER_METADATA.get(
            header,
            {
                "category": "HTTP",
                "severity": "Informational",
                "recommendation": "Review this header."
            }
        )

        details[header] = {
            "status": status,
            "value": value,
            "category": metadata["category"],
            "severity": metadata["severity"],
            "recommendation": metadata["recommendation"]
        }

    return details


def calculate_score(details):

    # Score is based only on your original five
    # security headers.
    weights = {
        "content-security-policy": 30,
        "strict-transport-security": 25,
        "x-frame-options": 15,
        "x-content-type-options": 15,
        "referrer-policy": 15
    }

    score = 0

    for header, weight in weights.items():

        status = details[header]["status"]

        if status == "PRESENT":
            score += weight

        elif status == "WEAK":
            score += weight * 0.5

    return round(score)


def analyze_cookies(response):

    cookies = []

    for cookie in response.headers.get_list("set-cookie"):

        name = cookie.split(
            ";",
            1
        )[0].split(
            "=",
            1
        )[0].strip()

        lowered = cookie.lower()

        if "samesite=strict" in lowered:
            same_site = "Strict"

        elif "samesite=lax" in lowered:
            same_site = "Lax"

        elif "samesite=none" in lowered:
            same_site = "None"

        else:
            same_site = None

        cookies.append({
            "name": name,
            "secure": "secure" in lowered,
            "httponly": "httponly" in lowered,
            "samesite": same_site
        })

    return cookies


def analyze_cors(headers):

    origin = headers.get(
        "access-control-allow-origin"
    )

    credentials = headers.get(
        "access-control-allow-credentials"
    )

    if not origin:

        status = "Not configured"

    elif (
        origin == "*"
        and
        str(credentials).lower() == "true"
    ):

        status = "Wildcard origin with credentials"

    elif origin == "*":

        status = "Wildcard origin"

    else:

        status = "Specific origin configured"

    return {
        "status": status,
        "allow_origin": origin,
        "allow_credentials": credentials
    }


@app.post("/analyze")
async def analyze(data: URLRequest):

    start_time = time.perf_counter()
    error_message = None
    raw_headers = {}
    headers = {}
    response = None
    response_time = 0

    try:

        async with httpx.AsyncClient(timeout=10) as client:

            response = await client.get(
                str(data.url),
                follow_redirects=True
            )

        raw_headers = {
            str(k): str(v)
            for k, v in response.headers.items()
        }

        headers = {
            k.lower(): v
            for k, v in raw_headers.items()
        }

    except (httpx.TimeoutException, httpx.RequestError, httpx.HTTPError) as exc:

        error_message = (
            f"Could not connect to the target site. The URL may be unreachable, slow, or blocking requests. "
            f"Details: {exc.__class__.__name__}: {exc}"
        )

    response_time = round(
        (time.perf_counter() - start_time) * 1000,
        2
    )


    # =========================================================
    # YOUR ORIGINAL HEADER ANALYSIS
    # =========================================================

    analysis = {}

    for header in REQUIRED_HEADERS:

        if header in headers:

            analysis[header] = "PRESENT"

        else:

            analysis[header] = "MISSING"


    # =========================================================
    # EXTENDED ANALYSIS
    # =========================================================

    if response is not None:

        header_details = build_header_details(
            headers
        )

        security_score = calculate_score(
            header_details
        )

        cookies = analyze_cookies(
            response
        )

        cors = analyze_cors(
            headers
        )


        # Response information

        response_info = {

            "status_code": response.status_code,

            "reason": response.reason_phrase,

            "http_version": response.http_version,

            "response_time_ms": response_time,

            "content_type": response.headers.get(
                "content-type"
            ),

            "content_length": response.headers.get(
                "content-length"
            ),

            "server": response.headers.get(
                "server"
            ),

            "powered_by": response.headers.get(
                "x-powered-by"
            ),

            "final_url": str(response.url)
        }


        # Redirect information

        redirects = []

        for redirect in response.history:

            redirects.append({

                "status_code": redirect.status_code,

                "url": str(redirect.url),

                "location": redirect.headers.get(
                    "location"
                )
            })


        # Transport information

        transport = {

            "https": str(
                response.url
            ).lower().startswith(
                "https://"
            ),

            "final_url": str(
                response.url
            )
        }


        # Cache information

        cache_control = headers.get(
            "cache-control"
        )

        cache = {

            "cache_control": cache_control,

            "pragma": headers.get(
                "pragma"
            ),

            "configured": bool(
                cache_control
            )
        }


        # Information disclosure

        information_disclosure = {

            "server": headers.get(
                "server"
            ),

            "x-powered-by": headers.get(
                "x-powered-by"
            ),

            "status": (

                "Server-identifying headers present"

                if (
                    headers.get("server")
                    or
                    headers.get("x-powered-by")
                )

                else

                "No common server-identifying headers found"
            )
        }

    else:

        header_details = build_header_details({})
        security_score = 0
        cookies = []
        cors = {
            "status": "Not checked",
            "allow_origin": None,
            "allow_credentials": None
        }
        response_info = {
            "status_code": None,
            "reason": "Connection failed",
            "http_version": "Unknown",
            "response_time_ms": response_time,
            "content_type": None,
            "content_length": None,
            "server": None,
            "powered_by": None,
            "final_url": str(data.url)
        }
        redirects = []
        transport = {
            "https": str(data.url).lower().startswith("https://"),
            "final_url": str(data.url)
        }
        cache = {
            "cache_control": None,
            "pragma": None,
            "configured": False
        }
        information_disclosure = {
            "server": None,
            "x-powered-by": None,
            "status": "Could not inspect headers because connection failed"
        }


    # =========================================================
    # LLM INTEGRATION
    # YOUR ORIGINAL GROQ CONFIGURATION IS KEPT
    # =========================================================

    GROQ_API_KEY = os.getenv(
        "GROQ_API_KEY"
    )


    if error_message:

        ai_analysis = error_message

    elif not GROQ_API_KEY:

        ai_analysis = (
            "GROQ_API_KEY not set. Add it to .env"
        )

    else:

        prompt = f"""
You are a senior web application security analyst. Analyze the supplied HTTP response data strictly from the evidence given.

Focus only on the five core security headers:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy

Main evaluation priorities:
1. Missing headers
2. Weak or permissive configurations
3. Practical security impact
4. Recommended remediation steps

SECURITY SCORE:
{security_score}/100

CORE HEADER ANALYSIS:
{analysis}

DETAILED HEADER ANALYSIS:
{header_details}

RAW RESPONSE HEADERS:
{raw_headers}

RESPONSE INFORMATION:
{response_info}

REDIRECTS:
{redirects}

TRANSPORT:
{transport}

COOKIES:
{cookies}

CORS:
{cors}

CACHE:
{cache}

INFORMATION DISCLOSURE:
{information_disclosure}

Output requirements:
- Base findings only on the supplied evidence.
- Do not invent vulnerabilities or assume every missing header is exploitable.
- Clearly distinguish among MISSING, WEAK, PRESENT, and INFO.
- Include the main risk drivers: missing headers, their impact, and actionable remediation guidance.
- Keep the output concise, professional, and easy to scan.
- Use markdown headings and short bullet points only.
- Do not add generic filler or long repeated explanations.

Use this structure exactly:

# Executive Summary

# Security Posture

## Missing Headers and Risk
- Header: ...
- Status: ...
- Impact: ...
- Recommended remediation: ...

## Existing Controls
- ...

# Prioritized Remediation Plan
### Priority 1
### Priority 2
### Priority 3

# Final Assessment
"""


        try:

            async with httpx.AsyncClient(
                timeout=20
            ) as client:

                resp = await client.post(

                    "https://api.groq.com/openai/v1/chat/completions",

                    headers={

                        "Authorization":
                            f"Bearer {GROQ_API_KEY}",

                        "Content-Type":
                            "application/json",
                    },

                    json={

                        "model":
                            "qwen/qwen3.8-27b",

                        "messages": [

                            {
                                "role":
                                    "system",

                                "content":
                                    "You are a helpful security assistant."
                            },

                            {
                                "role":
                                    "user",

                                "content":
                                    prompt
                            },

                        ],

                        "max_tokens":
                            600,

                        "temperature":
                            0.1,
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

                    if (
                        j
                        and
                        isinstance(j, dict)
                        and
                        j.get("error")
                    ):

                        err_msg = j[
                            "error"
                        ].get(
                            "message"
                        )

                    ai_analysis = (
                        f"Groq API error {status}: "
                        f"{err_msg or text[:500]}"
                    )


                else:

                    choices = (
                        j or {}
                    ).get(
                        "choices",
                        []
                    )


                    if (
                        choices
                        and
                        len(choices) > 0
                    ):

                        raw_content = (
                            choices[0]
                            .get(
                                "message",
                                {}
                            )
                            .get(
                                "content",
                                ""
                            )
                            or ""
                        )


                        if not raw_content:

                            ai_analysis = (
                                "Groq returned empty "
                                "content in choices."
                            )


                        else:
                            ai_analysis = raw_content.strip()
                    else:

                        ai_analysis = (
                            "No choices in Groq response. "
                            f"Raw: {text[:500]}"
                        )


        except Exception as e:

            ai_analysis = (
                f"Error calling Groq API: {e}"
            )


    # =========================================================
    # RETURN
    # =========================================================

    return {

        # YOUR ORIGINAL FIELDS
        "analysis": analysis,

        "ai_analysis": ai_analysis,

        "raw_headers": raw_headers,

        "status_code": None if response is None else response.status_code,

        "final_url": str(data.url),

        "error": error_message,


        # NEW FIELDS

        "security_score":
            security_score,

        "header_details":
            header_details,

        "cookies":
            cookies,

        "cors":
            cors,

        "cache":
            cache,

        "transport":
            transport,

        "response":
            response_info,

        "redirects":
            redirects,

        "redirect_count":
            len(redirects),

        "information_disclosure":
            information_disclosure
    }
