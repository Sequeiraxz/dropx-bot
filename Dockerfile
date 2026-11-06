FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl unzip && \
    curl -fsSL https://github.com/lune-org/lune/releases/download/v0.11.1/lune-0.11.1-linux-x86_64.zip -o /tmp/lune.zip && \
    unzip /tmp/lune.zip -d /usr/local/bin/ && \
    rm /tmp/lune.zip && \
    chmod +x /usr/local/bin/lune

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN cd Prometheus-Deobfuscator-main && npm install

CMD ["python", "bot.py"]
