FROM python:3.8.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openjdk-11-jdk && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN find /app/static_tools/jadx/bin -type f -exec sed -i 's/\r$//' {} \; \
    && chmod +x /app/static_tools/jadx/bin/jadx /app/static_tools/jadx/bin/jadx-gui

CMD ["python", "APKDeepLens.py", "--help"]
