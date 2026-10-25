"""LinkGuard - broken link detector for eLearning courses (Rise, Storyline 360, any SCORM/web export)."""
import asyncio, base64, csv, html as H, io, ipaddress, re, socket, time, uuid, zipfile
from collections import defaultdict
from urllib.parse import urlparse, urljoin, quote
import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse

app = FastAPI(title="LinkGuard")
JOBS: dict = {}
MAX_UNZIPPED = 500 * 1024 * 1024
UA = "Mozilla/5.0 (compatible; LinkGuard/1.0; course link audit)"
URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]},;|^`]+", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
REL_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#][^"']*)["']""", re.I)
TEXT_EXT = (".html", ".htm", ".js", ".json", ".xml", ".css", ".txt", ".md")
SKIP_FILES = (".min.js", "bundle", "vendor", "jquery", "polyfill")
NOISE = ("w3.org", "schemas.", "purl.org", "ns.adobe.com", "imsglobal.org", "adlnet.gov",
         "localhost", "127.0.0.1", "xmlns", "openxmlformats.org", "microsoft.com/office",
         "ecmascript.org", "reactjs.org", "fb.me", "github.com/facebook", "json-schema.org")
SOFT404 = re.compile(r"(page not found|404 not found|not found|no longer available|doesn.t exist|"
                     r"has been removed|content unavailable|oops)", re.I)


# ---------------------------------------------------------------- extraction
def norm(t: str) -> str:
    t = t.replace("\\/", "/").replace("\\u002F", "/").replace("\\u0026", "&").replace("\\u003d", "=")
    return H.unescape(t)


def urls_in(text: str):
    for m in URL_RE.finditer(norm(text)):
        u = m.group(0).rstrip(".,:;!?'\"")
        if not any(n in u.lower() for n in NOISE) and len(u) > 10:
            yield u


def scan_text(text: str, loc: str, out: list):
    for u in urls_in(text):
        out.append((u, loc))
    # Rise embeds its course JSON as base64 inside index.html / JS
    for b in B64_RE.findall(text):
        try:
            dec = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8")
        except Exception:
            continue
        if "http" in dec:
            for u in urls_in(dec):
                out.append((u, loc + " (embedded course data)"))


def extract_zip(data: bytes):
    out, local = [], []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Not a valid ZIP file")
    infos = z.infolist()
    if sum(i.file_size for i in infos) > MAX_UNZIPPED:
        raise HTTPException(400, "Package too large when unzipped")
    names = {i.filename for i in infos}
    for i in infos:
        n = i.filename
        if i.is_dir() or n.startswith("/") or ".." in n.split("/"):
            continue  # zip-slip guard; we never write to disk anyway
        low = n.lower()
        if not low.endswith(TEXT_EXT) or any(s in low for s in SKIP_FILES):
            continue
        text = z.read(n).decode("utf-8", "ignore")
        scan_text(text, n, out)
        if low.endswith((".html", ".htm")):
            base = n.rsplit("/", 1)[0] if "/" in n else ""
            for r in REL_RE.findall(text):
                if re.match(r"(?i)(https?:|mailto:|tel:|javascript:|data:|//)", r):
                    continue
                path = r.split("?")[0].split("#")[0]
                parts = []
                for p in ((base + "/" if base else "") + path).split("/"):
                    if p == "..": parts and parts.pop()
                    elif p not in ("", "."): parts.append(p)
                if "/".join(parts) not in names:
                    local.append(("/".join(parts), n))
    return out, local


async def crawl_live(url: str):
    """Optional: render a live Rise/Storyline URL with Playwright and collect links."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        raise HTTPException(501, "Install playwright to scan live URLs, or upload the ZIP export instead.")
    out = []
    async with async_playwright() as p:
        b = await p.chromium.launch()
        page = await b.new_page()
        await page.goto(url, wait_until="networkidle", timeout=45000)
        seen, queue = set(), [url]
        lessons = await page.eval_on_selector_all('a[href*="#/lessons"]', "e=>e.map(x=>x.href)")
        queue += list(dict.fromkeys(lessons))[:60]
        for u in queue:
            if u in seen: continue
            seen.add(u)
            await page.goto(u, wait_until="networkidle", timeout=45000)
            for sel in ('[aria-expanded="false"]', "[role=tab]"):
                for el in (await page.query_selector_all(sel))[:40]:
                    try: await el.click(timeout=800)
                    except Exception: pass
            for _ in range(15):
                await page.mouse.wheel(0, 1500); await page.wait_for_timeout(150)
            found = await page.eval_on_selector_all(
                "a[href],iframe[src],video[src],source[src],embed[src],object[data]",
                "e=>e.map(x=>x.href||x.src||x.data)")
            scan_text("\n".join(found) + "\n" + await page.content(), u, out)
        await b.close()
    return [(u, l) for u, l in out if not u.startswith(url.split("#")[0] + "#")]


# ---------------------------------------------------------------- checking
async def guard(url: str):
    pu = urlparse(url)
    if pu.scheme not in ("http", "https") or not pu.hostname:
        raise ValueError("unsupported scheme")
    infos = await asyncio.get_running_loop().getaddrinfo(pu.hostname, pu.port or 443, type=socket.SOCK_STREAM)
    for inf in infos:  # SSRF protection: refuse private/loopback/link-local targets
        if not ipaddress.ip_address(inf[4][0]).is_global:
            raise PermissionError("blocked private address")


async def fetch(client, url, method):
    cur, hops = url, 0
    while True:
        await guard(cur)
        async with client.stream(method, cur, follow_redirects=False) as r:
            body = b""
            if method == "GET":
                async for c in r.aiter_bytes():
                    body += c
                    if len(body) > 65536: break
            if r.is_redirect and hops < 6 and "location" in r.headers:
                cur, hops = urljoin(cur, r.headers["location"]), hops + 1
                continue
            return r.status_code, dict(r.headers), body, cur, hops


def oembed(url: str):
    pu = urlparse(url); h = (pu.hostname or "").lower().replace("www.", "")
    if h in ("youtube.com", "m.youtube.com", "youtube-nocookie.com", "youtu.be"):
        m = re.search(r"(?:embed/|shorts/|v=|youtu\.be/)([\w-]{11})", url)
        if m:
            return "YouTube", "https://www.youtube.com/oembed?format=json&url=" + quote(f"https://www.youtube.com/watch?v={m.group(1)}", safe="")
    if h in ("vimeo.com", "player.vimeo.com"):
        m = re.search(r"(?:video/|vimeo\.com/)(\d+)", url)
        if m:
            return "Vimeo", "https://vimeo.com/api/oembed.json?url=" + quote(f"https://vimeo.com/{m.group(1)}", safe="")
    return None


async def check_one(client, url):
    """Returns (status, detail). status: working|redirected|broken|review"""
    try:
        ov = oembed(url)
        if ov:
            code, *_ = await fetch(client, ov[1], "GET")
            if code == 200: return "working", f"{ov[0]} video available"
            if code in (404, 400, 410): return "broken", f"{ov[0]} video removed or not found"
            if code == 401: return "broken", f"{ov[0]} video private or embedding disabled"
            return "review", f"{ov[0]} oEmbed returned {code}"
        code, hdr, body, final, hops = await fetch(client, url, "HEAD")
        if code >= 400 or code in (405, 501):  # many servers reject HEAD
            code, hdr, body, final, hops = await fetch(client, url, "GET")
        elif code < 400 and (".pdf" in url.lower() or "html" in hdr.get("content-type", "")):
            code, hdr, body, final, hops = await fetch(client, url, "GET")
        ctype = hdr.get("content-type", "").lower()
        if code in (404, 410): return "broken", f"HTTP {code}"
        if code in (401, 403, 429, 999) or code == 503 and "cloudflare" in hdr.get("server", "").lower():
            return "review", f"HTTP {code} (login wall or bot blocking; verify manually)"
        if code >= 500: return "broken", f"HTTP {code} server error"
        if code >= 400: return "broken", f"HTTP {code}"
        if url.lower().split("?")[0].endswith(".pdf") and body and not body.startswith(b"%PDF"):
            return "broken", "Expected a PDF but got something else"
        if "html" in ctype and body:
            t = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            title = t.group(1).decode("utf-8", "ignore") if t else ""
            if SOFT404.search(title):
                return "review", f"Possible soft 404 (page title: {title.strip()[:60]})"
        if hops or final.rstrip("/") != url.rstrip("/"):
            return "redirected", f"Redirects to {final}"
        return "working", f"HTTP {code}"
    except PermissionError as e: return "broken", str(e)
    except socket.gaierror: return "broken", "DNS lookup failed (domain does not exist)"
    except httpx.ConnectError as e:
        return ("broken", "DNS lookup failed") if "Name or service" in str(e) or "getaddrinfo" in str(e) else ("review", f"Connection error: {e}")
    except httpx.TimeoutException: return "review", "Timed out"
    except ssl_errors() as e: return "review", f"SSL/TLS error: {e}"
    except Exception as e: return "review", f"{type(e).__name__}: {e}"


def ssl_errors():
    import ssl
    return ssl.SSLError


async def run_job(job_id, found, local):
    job = JOBS[job_id]
    locs = defaultdict(set)
    for u, l in found: locs[u].add(l)
    job["total"] = len(locs) + len(local)
    for path, src in local:
        job["results"].append(dict(url=path, status="broken", detail="Referenced file missing from package", locations=[src]))
        job["done"] += 1
    glob, per = asyncio.Semaphore(20), defaultdict(lambda: asyncio.Semaphore(2))
    async with httpx.AsyncClient(headers={"User-Agent": UA}, timeout=15, verify=True) as client:
        async def work(u, attempt=0):
            async with glob, per[urlparse(u).hostname]:
                st, d = await check_one(client, u)
            return st, d
        async def task(u):
            st, d = await work(u)
            if st in ("broken", "review") and not d.startswith(("DNS", "blocked", "YouTube", "Vimeo")) and "404" not in d:
                await asyncio.sleep(4)  # re-check transient failures before flagging
                st, d = await work(u)
            job["results"].append(dict(url=u, status=st, detail=d, locations=sorted(locs[u])[:8]))
            job["done"] += 1
        await asyncio.gather(*(task(u) for u in locs))
    job["state"] = "finished"; job["finished"] = time.time()


# ---------------------------------------------------------------- API
@app.post("/api/scan")
async def scan(file: UploadFile | None = File(None), url: str = Form("")):
    if file and file.filename:
        found, local = extract_zip(await file.read()); name = file.filename
    elif url.strip():
        found, local = await crawl_live(url.strip()), []; name = url.strip()
    else:
        raise HTTPException(400, "Provide a ZIP export or a course URL")
    jid = uuid.uuid4().hex[:10]
    JOBS[jid] = dict(id=jid, name=name, state="running", total=0, done=0, results=[], started=time.time())
    asyncio.create_task(run_job(jid, found, local))
    return {"job_id": jid, "links_found": len({u for u, _ in found}) + len(local)}


@app.get("/api/jobs/{jid}")
def job(jid: str):
    if jid not in JOBS: raise HTTPException(404, "Unknown job")
    return JOBS[jid]


@app.get("/api/jobs/{jid}.csv", response_class=PlainTextResponse)
def csv_export(jid: str):
    j = JOBS.get(jid) or HTTPException(404)
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["status", "url", "detail", "found_in"])
    for r in sorted(j["results"], key=lambda r: r["status"]):
        w.writerow([r["status"], r["url"], r["detail"], " | ".join(r["locations"])])
    return buf.getvalue()


PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>LinkGuard</title><style>
body{font:15px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
.box{border:1px solid #ddd;border-radius:10px;padding:1rem;margin:1rem 0}
input,button{font:inherit;padding:.5rem .8rem;border-radius:6px;border:1px solid #bbb}
button{background:#1a56db;color:#fff;border:0;cursor:pointer}
.chips span{display:inline-block;margin-right:.5rem;padding:.3rem .7rem;border-radius:99px;cursor:pointer;border:1px solid #ccc}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.4rem;border-bottom:1px solid #eee;vertical-align:top;word-break:break-all}
.broken{color:#b91c1c}.review{color:#b45309}.working{color:#15803d}.redirected{color:#1d4ed8}
progress{width:100%}small{color:#666}</style>
<h1>LinkGuard</h1><p>Upload a Storyline 360 / Rise export (ZIP) or enter a live course URL to find broken links.</p>
<div class=box><input type=file id=f accept=.zip> &nbsp;or&nbsp; <input id=u placeholder="https://rise.articulate.com/share/..." size=40>
<button onclick=go()>Scan</button><div id=msg></div></div>
<div id=out hidden><progress id=p></progress><div class=chips id=chips></div><p><a id=csv href=#>Download CSV</a></p>
<table><thead><tr><th>Status<th>Link<th>Detail<th>Found in</thead><tbody id=rows></tbody></table></div>
<script>
let jid,filter="issues";
async function go(){const fd=new FormData();const f=document.getElementById('f').files[0];
if(f)fd.append('file',f);fd.append('url',document.getElementById('u').value);
const r=await fetch('/api/scan',{method:'POST',body:fd});const j=await r.json();
if(!r.ok){msg.textContent=j.detail;return}msg.textContent=j.links_found+' links found, checking...';
jid=j.job_id;out.hidden=false;csv.href='/api/jobs/'+jid+'.csv';poll()}
async function poll(){const j=await (await fetch('/api/jobs/'+jid)).json();render(j);if(j.state=='running')setTimeout(poll,1500)}
function render(j){p.max=j.total||1;p.value=j.done;const c={};j.results.forEach(r=>c[r.status]=(c[r.status]||0)+1);
chips.innerHTML='';[['issues','Broken + review'],['broken','Broken'],['review','Needs review'],['redirected','Redirected'],['working','Working'],['all','All']].forEach(([k,l])=>{
const s=document.createElement('span');const n=k=='issues'?(c.broken||0)+(c.review||0):k=='all'?j.results.length:(c[k]||0);
s.textContent=l+' ('+n+')';if(k==filter)s.style.background='#e8eefc';s.onclick=()=>{filter=k;render(j)};chips.append(s)});
rows.innerHTML='';j.results.filter(r=>filter=='all'||(filter=='issues'?r.status=='broken'||r.status=='review':r.status==filter))
.sort((a,b)=>a.status.localeCompare(b.status)).forEach(r=>{const tr=rows.insertRow();
const t=(i,x,cl)=>{const d=tr.insertCell();d.textContent=x;if(cl)d.className=cl};
t(0,r.status,r.status);t(1,r.url);t(2,r.detail);t(3,r.locations.join(', '))})}
</script>"""


@app.get("/", response_class=HTMLResponse)
def index(): return PAGE
