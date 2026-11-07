FROM python:3.12-slim
WORKDIR /app
ENV SQLITE_TMPDIR=/data/.sqlite-tmp TMPDIR=/data/.sqlite-tmp
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app/ /app/
# Seed Docker-managed named volumes with an owner-writable SQLite data
# directory. Docker copies this directory's ownership into an empty volume.
RUN useradd -r -u 10001 -g users monitor \
    && mkdir -p /data/.sqlite-tmp \
    && chown -R 10001:100 /data \
    && chmod 700 /data/.sqlite-tmp
USER 10001:100
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD python -c "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8080/api/startup',timeout=3)).get('ready') is True" || exit 1
CMD ["python","-u","/app/main.py"]
