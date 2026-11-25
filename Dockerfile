FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git g++ make pkg-config libssl-dev openssl unzip zip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# بناء zsign
RUN git clone --depth 1 https://github.com/zhlynn/zsign.git /tmp/zsign \
    && cd /tmp/zsign/build/linux && make clean && make \
    && cp "$(find /tmp/zsign -type f -name zsign -perm -u+x | head -1)" /usr/local/bin/zsign \
    && rm -rf /tmp/zsign \
    && zsign -v || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bot.py .

CMD ["python", "bot.py"]
