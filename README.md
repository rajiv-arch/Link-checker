LinkGuard
Broken-link detector for eLearning courses.
pip install -r requirements.txt
uvicorn app:app --reload        # open http://localhost:8000
Inputs: ZIP export of Storyline 360 / Rise (Web or SCORM), or a live course URL (needs Playwright). Statuses: Working, Redirected, Broken, Needs review (bot blocking, login walls, timeouts, possible soft 404). Built in: safe ZIP handling (package JS is never executed), SSRF blocking, per-domain rate limits, retry before flagging, YouTube/Vimeo oEmbed checks, PDF type check, missing-file check, Rise base64 course-data decoding.
Production next steps: persistent DB + job queue (Redis/Celery), auth, scheduled re-scans, per-lesson location labels.
