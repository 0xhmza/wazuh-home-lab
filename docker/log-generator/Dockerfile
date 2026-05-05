FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY app /app/app

CMD ["python", "app/generate_logs.py", "--config", "/config/lab-runtime.json", "--output-root", "/training-data"]
