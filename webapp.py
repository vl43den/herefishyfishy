from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn
import asyncio
from prototype import score_domain, load_whitelist, load_threat_feed, configure_proxy

app = FastAPI(title="HereFishyFishy Web")

HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>HereFishyFishy</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        input[type=text] { width: 300px; padding: 8px; }
        button { padding: 8px 16px; }
        .result { margin-top: 20px; }
    </style>
</head>
<body>
    <h1>HereFishyFishy Domain Score</h1>
    <form action="/score" method="get">
        <input type="text" name="domain" placeholder="example.com" required />
        <button type="submit">Analyze</button>
    </form>
    {result}
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML_FORM.format(result="")

@app.get("/score", response_class=HTMLResponse)
async def analyze(domain: str):
    result = await score_domain(domain)
    html_result = f"<div class='result'><h2>Score: {result['score']}</h2><pre>{result['details']}</pre></div>"
    return HTML_FORM.format(result=html_result)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
