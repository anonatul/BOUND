# Stage 1: build frontend
FROM node:20-slim AS frontend-builder
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend ./
RUN npm run build

# Stage 2: backend
FROM python:3.11-slim

# Install system deps for pymupdf, cryptography, etc.
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv
RUN pip install uv

# Copy dependency files
COPY pyproject.toml README.md ./
COPY backend ./backend
COPY ledger ./ledger
COPY storage ./storage
# Copy built frontend
COPY --from=frontend-builder /frontend/dist ./frontend/dist

# Install dependencies (with uv sync, no dev)
RUN uv sync --python 3.11 --no-dev 2>&1 | tail -n 20 || uv sync --python 3.11

# Ensure ledger and storage dirs
RUN mkdir -p ledger/node1 ledger/node2 ledger/node3 ledger/node4 storage/encrypted storage/watermarked storage/uploads backend/keys

EXPOSE 8000

CMD ["uv", "run", "--python", "3.11", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
