FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./lab_app

ENV LAB_1_HOST=0.0.0.0
ENV LAB_1_PORT=5001

EXPOSE 5001

CMD ["python", "-m", "lab_app.app"]
