FROM python:3.12-alpine

RUN adduser --system --no-create-home app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY fail2banexporter fail2banexporter/

USER app
CMD ["python", "-m" , "fail2banexporter.main"]
