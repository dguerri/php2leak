FROM python:3.12-slim

# pwntools needs a C compiler + libffi/ssl headers for some backends
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "pwntools>=4.13"

WORKDIR /exploit
COPY leak.py /exploit/leak.py

CMD ["python3", "/exploit/leak.py"]
