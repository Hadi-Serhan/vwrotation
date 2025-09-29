FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
ENV PYTHONUNBUFFERED=1

# default: run the loop
CMD ["python", "-m", "vaultwarden_scheduler.service"]
