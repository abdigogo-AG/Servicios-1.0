FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim-bookworm

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv

# Copia el contenido de la carpeta api_code a la raíz del contenedor
COPY ./api_code/ .

# Copia la carpeta frontend
COPY ./frontend/ ./frontend/

ENV PATH="/opt/venv/bin:$PATH"

# Puerto 8080 para Render
EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]