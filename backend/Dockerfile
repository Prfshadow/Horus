# HORUS backend — FastAPI + uvicorn.
# SQLite lives at /data/horus.db (mount a volume there for persistence).
# Build from the repo root:  docker build -f backend/Dockerfile ./backend
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first (better layer caching).
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Application code.
COPY app/ ./app/
COPY alembic.ini ./
COPY alembic/ ./alembic/

# Runtime defaults (compose /.env overrides these; secrets stay out of the image).
ENV APP_NAME=Horus \
    APP_ENV=prod \
    LOG_LEVEL=INFO \
    DATABASE_URL=sqlite:////data/horus.db \
    PORT=8000

EXPOSE 8000

# in-container healthcheck needs no extra packages (stdlib urllib).
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import sys,urllib.request,os; port=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://localhost:{port}/api/v1/health', timeout=5).status == 200 else 1)"

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
