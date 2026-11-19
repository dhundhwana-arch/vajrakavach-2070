FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VAJRA_HOST=0.0.0.0 \
    VAJRA_PORT=8080 \
    VAJRA_DB_PATH=/app/data/vajrakavach.db

COPY . /app

RUN mkdir -p /app/data && useradd -m vajra && chown -R vajra:vajra /app
USER vajra

EXPOSE 8080

CMD ["python3", "-m", "backend.app"]
