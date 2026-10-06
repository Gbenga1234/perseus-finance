"""Container entrypoint: ``python -m perseus_common.server``.

Configured through environment variables so one image layout works for every service.
"""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        os.environ["APP_FACTORY"],
        factory=True,
        host=os.environ.get("HOST", "0.0.0.0"),  # noqa: S104  # nosec B104 - bound inside a container
        port=int(os.environ.get("PORT", "8000")),
        workers=int(os.environ.get("WEB_CONCURRENCY", "1")),
        proxy_headers=True,
        # Only trust X-Forwarded-* from the edge proxy, never from arbitrary clients.
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        server_header=False,
        access_log=False,
        log_config=None,
        timeout_keep_alive=5,
        timeout_graceful_shutdown=20,
    )


if __name__ == "__main__":
    main()
