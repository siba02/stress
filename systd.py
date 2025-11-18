import time
import argparse
import logging
import logging.handlers
import os
import sys
import subprocess
from datetime import datetime
from random import choice, randint

DEFAULT_TAG = "pylogtest"

LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "NOTICE": 25,   # logging doesn't have NOTICE by default; we'll treat as 25
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

# Try to import systemd journal bindings (optional)
try:
    from systemd import journal as _journal
    HAVE_SYSTEMD_JOURNAL = True
except Exception:
    HAVE_SYSTEMD_JOURNAL = False


def send_via_systemd_journal(message: str, priority: int, tag: str):
    """Send to systemd journal via python bindings (if available)."""
    if not HAVE_SYSTEMD_JOURNAL:
        raise RuntimeError("systemd.journal python bindings not available")
    # _journal.send accepts keyword fields
    # Use SYSLOG_IDENTIFIER so journalctl -t <tag> will match
    _journal.send(message,
                  SYSLOG_IDENTIFIER=tag,
                  PRIORITY=str(priority))


def make_syslog_logger(tag: str):
    """Return a logger configured to write to /dev/log or fallback to localhost UDP syslog."""
    logger = logging.getLogger(tag)
    logger.setLevel(logging.DEBUG)
    # avoid adding duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    # try UNIX domain socket first (common on systemd systems)
    addresses = ['/dev/log', '/run/systemd/journal/dev-log']
    handler = None
    for addr in addresses:
        if os.path.exists(addr):
            try:
                handler = logging.handlers.SysLogHandler(address=addr)
                break
            except Exception:
                handler = None

    # fallback to UDP localhost:514 (less ideal)
    if handler is None:
        try:
            handler = logging.handlers.SysLogHandler(address=('127.0.0.1', 514))
        except Exception:
            handler = None

    if handler is None:
        raise RuntimeError("No syslog socket available and UDP fallback failed")

    formatter = logging.Formatter('%(asctime)s %(name)s[%(process)d]: %(levelname)s: %(message)s',
                                  datefmt='%Y-%m-%dT%H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    # Add an extra StreamHandler so when run interactively you also see prints locally
    stream_h = logging.StreamHandler(sys.stdout)
    stream_h.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(stream_h)
    return logger


def send_via_logger_cmd(message: str, level: str, tag: str):
    """Use the 'logger' command-line utility as a last resort."""
    cmd = ['logger', '-t', tag, f'[{level}] {message}']
    # don't let subprocess output disturb the terminal
    subprocess.run(cmd)


def priority_for_level(level_name: str) -> int:
    # systemd priorities: 0=emerg .. 7=debug (inverse of Python numeric)
    # Map common levels to syslog priorities (0..7). We'll use: CRITICAL=2, ERROR=3, WARNING=4, INFO=6, DEBUG=7
    mapping = {
        "CRITICAL": 2,
        "ERROR": 3,
        "WARNING": 4,
        "INFO": 6,
        "DEBUG": 7,
        "NOTICE": 5,
    }
    return mapping.get(level_name.upper(), 6)  # default INFO


def main():
    parser = argparse.ArgumentParser(description="Generate system logs to be viewed with journalctl.")
    parser.add_argument('--rate', type=float, default=1.0, help='messages per second (can be fractional).')
    parser.add_argument('--count', type=int, default=0, help='number of messages to send; 0 = unlimited.')
    parser.add_argument('--tag', type=str, default=DEFAULT_TAG, help='syslog/journal tag (identifier).')
    parser.add_argument('--level', type=str, default='INFO', choices=list(LEVEL_MAP.keys()), help='log level.')
    parser.add_argument('--randomize', action='store_true', help='randomize messages and levels.')
    args = parser.parse_args()

    interval = 1.0 / args.rate if args.rate > 0 else 0
    tag = args.tag
    level = args.level.upper()

    # prepare syslog logger if possible
    logger = None
    use_systemd_api = False
    try:
        if HAVE_SYSTEMD_JOURNAL:
            use_systemd_api = True
            print("Using systemd.journal Python bindings (systemd API).")
        else:
            logger = make_syslog_logger(tag)
            print("Using SysLogHandler to /dev/log or UDP.")
    except Exception as e:
        print("Could not configure SysLogHandler:", e)
        logger = None

    sent = 0
    sample_messages = [
        "User login succeeded",
        "User login failed: invalid password",
        "Background job completed",
        "Periodic health check OK",
        "Disk usage threshold crossed",
        "Connection to upstream timed out",
        "Config reload requested",
        "Cache miss for key user:1234",
        "Worker spawned successfully",
        "Unhandled exception in worker thread",
    ]
    sample_levels = ["DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"]

    try:
        while args.count == 0 or sent < args.count:
            if args.randomize:
                msg = choice(sample_messages)
                lvl = choice(sample_levels)
            else:
                msg = sample_messages[sent % len(sample_messages)]
                lvl = level

            timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
            full_msg = f"{msg} (seq={sent+1}, time={timestamp}, host={os.uname().nodename})"

            # try systemd API first
            if use_systemd_api:
                priority = priority_for_level(lvl)
                try:
                    send_via_systemd_journal(full_msg, priority, tag)
                except Exception as e:
                    # if that fails, fall back to logger/syslog
                    use_systemd_api = False
                    print("systemd.journal send failed, falling back:", e)
                    if logger is None:
                        try:
                            logger = make_syslog_logger(tag)
                        except Exception as e2:
                            print("Failed to configure syslog logger:", e2)
                            logger = None

            if not use_systemd_api:
                if logger is not None:
                    # map level str to logging level or numeric
                    py_level = LEVEL_MAP.get(lvl, logging.INFO)
                    # If NOTICE (25) not understood by logging basic config, just use INFO
                    if py_level == 25:
                        py_level = logging.INFO
                    logger.log(py_level, full_msg)
                else:
                    # last resort: call 'logger' command
                    send_via_logger_cmd(full_msg, lvl, tag)

            sent += 1
            if interval > 0:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nInterrupted by user, exiting.")

if __name__ == "__main__":
    main()

