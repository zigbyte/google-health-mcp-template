FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# Pre-compile bytecode for faster cold starts on Cloud Run
RUN python -m compileall -q /usr/local/lib/python3.12/site-packages /app

# Run as non-root user
RUN useradd --create-home appuser
USER appuser

EXPOSE 8080

CMD ["python", "server.py"]
