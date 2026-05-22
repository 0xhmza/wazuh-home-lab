FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" pycryptodome

COPY app /app/app

EXPOSE 8080

CMD ["python", "app/api.py", \
     "--config", "/config/lab-runtime.json", \
     "--output-root", "/training-data", \
     "--host", "0.0.0.0", "--port", "8080"]
