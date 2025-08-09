FROM python:3.13-alpine3.22@sha256:f196fd275fdad7287ccb4b0a85c2e402bb8c794d205cf6158909041c1ee9f38d

RUN apk update \
    && rm -rf /var/cache/apk/*

RUN adduser --system --no-create-home app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY fail2banexporter fail2banexporter/

USER app
CMD ["python", "-m" , "fail2banexporter.main"]
