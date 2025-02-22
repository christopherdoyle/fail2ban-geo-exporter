FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY fail2banexporter fail2banexporter/

CMD ["python", "-m" , "fail2banexporter.main"]
