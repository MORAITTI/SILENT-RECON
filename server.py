import asyncio
import contextlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import time

from collections import OrderedDict, deque
from datetime import datetime, timezone
from pathlib import Path

from aiohttp import web

BASE_DIR = Path(__file__).resolve().parent

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8080"))
DASHBOARD_TOKEN = os.getenv("DASHBOARD_TOKEN", "")
SURICATA_EVE = os.getenv("SURICATA_EVE", "").strip()

MAX_EVENTS = 3000
MAX_SOURCES = 4096

HTTP_WINDOW = 30
           
