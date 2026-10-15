FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir \
  "fastapi>=0.116,<1" "uvicorn>=0.35,<1" \
  "psycopg[binary]>=3.2,<4" "prometheus-client>=0.20,<1" "psutil>=6,<8"
COPY app /app/app
RUN useradd --uid 10002 --create-home erp
USER erp
EXPOSE 8081
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
