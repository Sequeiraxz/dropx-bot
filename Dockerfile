# Fase 1: compila o luau e o luau-ast para Linux
FROM python:3.11-slim AS luau-build
RUN apt-get update && apt-get install -y --no-install-recommends g++ make git ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 0.726 https://github.com/luau-lang/luau /luau
WORKDIR /luau
RUN make config=release -j2 luau luau-ast

# Fase 2: imagem final
FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl unzip && \
    curl -fsSL https://github.com/lune-org/lune/releases/download/v0.11.1/lune-0.11.1-linux-x86_64.zip -o /tmp/lune.zip && \
    unzip /tmp/lune.zip -d /usr/local/bin/ && \
    rm /tmp/lune.zip && \
    chmod +x /usr/local/bin/lune

RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN cd Prometheus-Deobfuscator-main && npm install

# Dependências do Luraph e do luaobfuscator (só instala o que existir)
RUN for d in luraph-deobf luaobfuscator-deobf/luaobfuscator; do \
      if [ -f "$d/package.json" ]; then (cd "$d" && npm install --omit=dev); fi; \
      if [ -f "$d/requirements.txt" ]; then pip install --no-cache-dir -r "$d/requirements.txt"; fi; \
    done

# Binários Linux do Luau para o Luraph
COPY --from=luau-build /luau/build/release/luau /app/luraph-deobf/bin/luau
COPY --from=luau-build /luau/build/release/luau-ast /app/luraph-deobf/bin/luau-ast
RUN chmod +x /app/luraph-deobf/bin/luau /app/luraph-deobf/bin/luau-ast

ENV PYTHON_BIN=python

RUN useradd -m botuser && chown -R botuser:botuser /app
USER botuser

CMD ["python", "bot.py"]
