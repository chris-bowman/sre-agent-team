import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("main")


def log_event(event: str, **fields: Any) -> None:
    payload = {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    logger.info(json.dumps(payload, sort_keys=True, default=str))
