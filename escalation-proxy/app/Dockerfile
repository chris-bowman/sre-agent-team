FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
ARG PIP_INDEX_URL
RUN test -n "$PIP_INDEX_URL" \
	&& pip install --no-cache-dir --index-url "$PIP_INDEX_URL" -r requirements.txt

COPY main.py authorization.py contracts.py caller_policy.py investigation_registry.py investigation_service.py mcp_transport.py output_validation.py platform_client.py telemetry.py /app/

EXPOSE 8080

# Run as non-root
RUN adduser --disabled-password --gecos "" appuser
USER appuser

CMD ["python", "main.py"]
