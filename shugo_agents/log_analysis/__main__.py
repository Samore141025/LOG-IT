from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from shugo_agents.log_analysis.agent import LogAnalysisAgent


class JSONFormatter(logging.Formatter):
    """Structured JSON formatter for standard logging module."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "agent": "log_analysis",
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging(use_json: bool = True, log_level: str = "INFO") -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if use_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s"))

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]


def main() -> None:
    # Load environment variables from .env if present
    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="shugo-log-analysis",
        description="SHUGO Autonomous Log Analysis Agent (Agent #4)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to custom config.yaml file",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single processing batch and exit (for debugging / testing)",
    )
    parser.add_argument(
        "--plain-logs",
        action="store_true",
        help="Use plain text logging instead of structured JSON",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.getenv("LOG_LEVEL", "INFO"),
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )

    args = parser.parse_args()

    setup_logging(use_json=not args.plain_logs, log_level=args.log_level)
    logger = logging.getLogger("shugo.log_analysis")
    logger.info("Initializing SHUGO Log Analysis Agent...")

    agent = LogAnalysisAgent(config_path=args.config)

    logger.info(
        f"Starting agent loop (mode={'single-run' if args.once else 'continuous'}). "
        f"Database: {agent.app_config.database.url.split('@')[-1] if '@' in agent.app_config.database.url else 'local'}"
    )

    agent.run_loop(
        once=args.once,
        idle_sleep_seconds=agent.app_config.runtime.poll_interval_idle_seconds,
        busy_sleep_seconds=agent.app_config.runtime.poll_interval_busy_seconds,
        heartbeat_interval_seconds=agent.app_config.runtime.heartbeat_interval_seconds,
    )


if __name__ == "__main__":
    main()
