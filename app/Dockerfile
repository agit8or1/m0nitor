FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends snmp && rm -rf /var/lib/apt/lists/*
# requirements*.txt are the direct pins; *.lock are the hash-pinned full sets (pip-compile --generate-hashes)
COPY requirements.lock requirements-dev.lock ./
ARG DEV=0
RUN if [ "$DEV" = 1 ]; then L=requirements-dev.lock; else L=requirements.lock; fi && pip install --no-cache-dir --require-hashes -r "$L"
COPY netmon ./netmon
COPY tests ./tests
RUN useradd -u 10001 -r -s /usr/sbin/nologin netmon
USER 10001
EXPOSE 8000
CMD ["uvicorn", "netmon.web:app", "--host", "0.0.0.0", "--port", "8000"]
