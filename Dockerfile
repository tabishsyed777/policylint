FROM python:3.12-slim
WORKDIR /app
COPY policylint.py /app/policylint.py
RUN useradd --create-home --uid 10001 appuser
USER appuser
ENTRYPOINT ["python", "/app/policylint.py"]
