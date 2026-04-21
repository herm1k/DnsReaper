FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY dnsreaper.py ./
COPY config.example.json ./
COPY sample_domains.txt ./
CMD ["python", "dnsreaper.py", "--source", "file", "--input-file", "sample_domains.txt"]
