FROM python:3.13-slim
COPY deploy/fakeapi/server.py /app/server.py
COPY deploy/runtime/certs/fakeapi.pem deploy/runtime/certs/fakeapi.key /certs/
RUN mkdir -p /log
CMD ["python", "/app/server.py"]
