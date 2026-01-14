FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 9348
ENV CONFIG_PATH=/etc/prometheus/idrac.yml
ENV VERIFY_TLS=false
ENV SESSION_TTL_SECONDS=600

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9348"]

