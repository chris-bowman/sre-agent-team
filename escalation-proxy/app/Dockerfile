FROM python:3.12-alpine@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a

WORKDIR /app

RUN apk upgrade --no-cache

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
