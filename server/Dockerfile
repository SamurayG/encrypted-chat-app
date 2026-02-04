FROM python:3.11-slim

WORKDIR /usr/src/server

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
 && pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "./server.py"]
