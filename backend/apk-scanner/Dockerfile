# Stage 1: Base avec dépendances système
FROM python:3.11-slim AS base

# Variables d'environnement
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    openjdk-21-jre-headless \
    aapt \
    wget \
    unzip \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Installer apktool
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool && \
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.1.jar -O /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool.jar

# Stage 2: Build Python dependencies
FROM base AS builder

WORKDIR /app

# Copier requirements.txt
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 3: Production
FROM base

# Créer un utilisateur non-root
RUN useradd -m -u 1000 scanner && \
    mkdir -p /app /app/uploads /app/output /app/database /app/logs /app/decompiled && \
    chown -R scanner:scanner /app

WORKDIR /app

# Copier les dépendances Python depuis le builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copier le code source
COPY --chown=scanner:scanner src/ ./src/
COPY --chown=scanner:scanner requirements.txt .

# Créer les fichiers __init__.py
RUN touch src/__init__.py && \
    touch src/utils/__init__.py && \
    touch src/database/__init__.py

# Exposer le port
EXPOSE 5000

# Utiliser l'utilisateur non-root
USER scanner

# Variables d'environnement
ENV PORT=5000 \
    PYTHONPATH=/app/src \
    DEBUG=False \
    NETWORK_INSPECTOR_URL=http://network-inspector:5001

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Démarrer l'application
CMD ["python", "src/main.py"]
