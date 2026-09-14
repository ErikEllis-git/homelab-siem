FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask gunicorn
COPY app.py .
RUN mkdir -p /app/logs
EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "2", "app:app"]
