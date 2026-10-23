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
HTTP_THRESHOLD = 10
ALERT_COOLDOWN = 30

INDEX_PATH = BASE_DIR / "index.html"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("silent-recon")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def clean(value, limit=500):
    """Ограничиваем размер данных, попадающих в журнал и API."""
    if value is None:
        return ""

    return str(value).replace("\x00", "")[:limit]


def normalized_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return "не определён"


class Monitor:
    def __init__(self):
        self.events = deque(maxlen=MAX_EVENTS)
        self.sequence = 0

        self.started_at = utc_now()

        self.http_total = 0
        self.network_total = 0
        self.alert_total = 0

        self.sources = OrderedDict()

        self.sensor = {
            "configured": bool(SURICATA_EVE),
            "connected": False,
            "message": (
                "Ожидание файла EVE"
                if SURICATA_EVE
                else "Suricata не подключена"
            ),
            "last_event_at": None,
        }

    def emit(self, kind, source, message, **fields):
        self.sequence += 1

        event = {
            "id": self.sequence,
            "time": utc_now(),
            "kind": kind,
            "source": source,
            "message": clean(message, 1000),
        }

        event.update(fields)
        self.events.append(event)

        if kind == "alert":
            self.alert_total += 1

        return event

    def record_http(self, request, status, duration_ms):
        # Не доверяем X-Forwarded-For из произвольного клиентского запроса.
        # За reverse proxy настройте получение клиентского IP отдельно.
        ip = normalized_ip(request.remote)

        self.http_total += 1

        self.emit(
            kind="http",
            source="HTTP",
            message="HTTP-запрос к наблюдаемому обработчику",
            src_ip=ip,
            method=clean(request.method, 20),
            path=clean(request.path_qs, 500),
            status=status,
            user_agent=clean(request.headers.get("User-Agent", ""), 350),
            duration_ms=round(duration_ms, 2),
        )

        now = time.monotonic()

        entry = self.sources.get(ip)

        if entry is None:
            entry = {
                "times": deque(),
                "last_alert": float("-inf"),
            }
            self.sources[ip] = entry

        self.sources.move_to_end(ip)

        while len(self.sources) > MAX_SOURCES:
            self.sources.popitem(last=False)

        times = entry["times"]

        while times and now - times[0] >= HTTP_WINDOW:
            times.popleft()

        times.append(now)

        # Для эвристики достаточно ограниченного числа временных отметок.
        while len(times) > 1000:
            times.popleft()

        if (
            len(times) >= HTTP_THRESHOLD
            and now - entry["last_alert"] >= ALERT_COOLDOWN
        ):
            entry["last_alert"] = now

            self.emit(
                kind="alert",
                source="HTTP heuristic",
                message=(
                    f"Необычная частота HTTP-запросов: "
                    f"не менее {len(times)} за {HTTP_WINDOW} секунд. "
                    "Это эвристика, а не доказательство сканирования."
                ),
                src_ip=ip,
                severity=3,
            )

    def record_suricata(self, record):
        event_type = record.get("event_type")

        # Другие типы EVE можно добавить при необходимости.
        if event_type not in {"alert", "flow", "http"}:
            return

        self.network_total += 1

        common = {
            "src_ip": clean(record.get("src_ip"), 64),
            "src_port": record.get("src_port"),
            "dest_ip": clean(record.get("dest_ip"), 64),
            "dest_port": record.get("dest_port"),
            "protocol": clean(record.get("proto"), 20),
            "observed_at": clean(record.get("timestamp"), 80),
        }

        if event_type == "alert":
            alert = record.get("alert") or {}

            self.emit(
                kind="alert",
                source="Suricata",
                message=clean(
                    alert.get("signature") or "Предупреждение Suricata",
                    1000,
                ),
                category=clean(alert.get("category"), 200),
                severity=alert.get("severity"),
                signature_id=alert.get("signature_id"),
                **common,
            )

        elif event_type == "http":
            http = record.get("http") or {}

            self.emit(
                kind="network",
                source="Suricata HTTP",
                message="HTTP-событие сетевого сенсора",
                method=clean(http.get("http_method"), 20),
                path=clean(http.get("url"), 500),
                status=http.get("status"),
                user_agent=clean(http.get("http_user_agent"), 350),
                **common,
            )

        else:
            flow = record.get("flow") or {}

            self.emit(
                kind="network",
                source="Suricata flow",
                message=(
                    f"Сетевой поток: "
                    f"{clean(flow.get('state') or 'unknown', 40)}"
                ),
                packets_to_server=flow.get("pkts_toserver"),
                packets_to_client=flow.get("pkts_toclient"),
                **common,
            )

    def snapshot(self, since):
        items = list(self.events)

        # Если клиент сильно отстал, часть истории уже могла быть удалена.
        truncated = bool(
            items
            and since > 0
            and since < items[0]["id"] - 1
        )

        batch = [
            event for event in items
            if event["id"] > since
        ][:200]

        cursor = batch[-1]["id"] if batch else since

        return {
            "events": batch,
            "cursor": cursor,
            "latest": self.sequence,
            "truncated": truncated,
            "server_time": utc_now(),
            "started_at": self.started_at,
            "stats": {
                "http": self.http_total,
                "network": self.network_total,
                "alerts": self.alert_total,
                "stored": len(self.events),
            },
            "sensor": dict(self.sensor),
        }


monitor = Monitor()


def authorized(request):
    provided = request.headers.get("Authorization", "")
    expected = f"Bearer {DASHBOARD_TOKEN}"

    return hmac.compare_digest(
        provided.encode("utf-8"),
        expected.encode("utf-8"),
    )


@web.middleware
async def security_headers(request, handler):
    response = await handler(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"

    return response


async def dashboard(request):
    nonce = secrets.token_urlsafe(24)

    html = INDEX_PATH.read_text(encoding="utf-8")
    html = html.replace("__NONCE__", nonce)

    response = web.Response(text=html, content_type="text/html")

    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )

    return response


async def api_events(request):
    if not authorized(request):
        return web.json_response(
            {"error": "Требуется корректный токен"},
            status=401,
        )

    try:
        since = int(request.query.get("since", "0"))

        if since < 0:
            raise ValueError
    except ValueError:
        return web.json_response(
            {"error": "Некорректный параметр since"},
            status=400,
        )

    return web.json_response(monitor.snapshot(since))


async def favicon(request):
    return web.Response(status=204)


async def observed_request(request):
    started = time.perf_counter()

    status = 200 if request.path == "/probe" else 404

    monitor.record_http(
        request,
        status,
        (time.perf_counter() - started) * 1000,
    )

    return web.json_response(
        {
            "service": "SILENT-RECON",
            "message": (
                "Запрос зарегистрирован"
                if status == 200
                else "Ресурс не найден; запрос зарегистрирован"
            ),
        },
        status=status,
    )


async def tail_suricata():
    """
    Читаем только новые строки после подключения.

    Обрабатываем:
    - появление файла после старта;
    - замену файла при ротации;
    - усечение;
    - неполную последнюю строку.

    Чтение предполагает локальный обычный файл.
    Для сетевых файловых систем лучше отдельный сборщик событий.
    """
    path = Path(SURICATA_EVE)
    file = None
    identity = None
    first_open = True
    previous_error = None

    try:
        while True:
            try:
                stat = path.stat()
                current_identity = (stat.st_dev, stat.st_ino)

                if file is None or current_identity != identity:
                    if file is not None:
                        file.close()

                    file = path.open("rb")
                    identity = current_identity

                    if first_open:
                        file.seek(0, os.SEEK_END)
                        first_open = False

                elif stat.st_size < file.tell():
                    file.seek(0)

                monitor.sensor.update({
                    "connected": True,
                    "message": "Чтение новых событий EVE",
                })

                previous_error = None

                for _ in range(100):
                    position = file.tell()

                    # Ограничение размера одной строки — 1 МБ.
                    line = file.readline(1024 * 1024 + 1)

                    if not line:
                        break

                    if len(line) > 1024 * 1024:
                        # Пропускаем слишком большую запись до конца строки.
                        while line and not line.endswith(b"\n"):
                            line = file.readline(1024 * 1024)

                        logger.warning("Пропущена слишком большая строка EVE")
                        continue

                    if not line.endswith(b"\n"):
                        file.seek(position)
                        break

                    try:
                        record = json.loads(line)

                        if not isinstance(record, dict):
                            continue

                        monitor.record_suricata(record)
                        monitor.sensor["last_event_at"] = utc_now()

                    except (ValueError, TypeError):
                        logger.warning("Некорректная JSON-строка в EVE")

            except (OSError, ValueError) as error:
                monitor.sensor.update({
                    "connected": False,
                    "message": f"Не удалось прочитать EVE: {type(error).__name__}",
                })

                error_key = (type(error).__name__, str(error))

                if error_key != previous_error:
                    logger.warning("Ошибка чтения EVE: %s", error)
                    previous_error = error_key

                if file is not None:
                    file.close()

                file = None
                identity = None

            await asyncio.sleep(0.25)

    finally:
        if file is not None:
            file.close()


async def sensor_context(app):
    task = None

    if SURICATA_EVE:
        task = asyncio.create_task(tail_suricata())

    yield

    if task is not None:
        task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await task


def create_app():
    app = web.Application(
        middlewares=[security_headers],
        client_max_size=64 * 1024,
    )

    # Служебные обращения панели не попадают в наблюдаемый HTTP-журнал,
    # чтобы панель не обнаруживала собственный polling как "сканирование".
    app.router.add_get("/", dashboard)
    app.router.add_get("/index.html", dashboard)
    app.router.add_get("/api/events", api_events)
    app.router.add_get("/favicon.ico", favicon)

    app.router.add_route("*", "/{path:.*}", observed_request)

    app.cleanup_ctx.append(sensor_context)

    return app


if __name__ == "__main__":
    if len(DASHBOARD_TOKEN) < 24:
        raise SystemExit(
            "Задайте DASHBOARD_TOKEN длиной не менее 24 символов. "
            "Для генерации: python -c \"import secrets; "
            "print(secrets.token_urlsafe(32))\""
        )

    if not INDEX_PATH.is_file():
        raise SystemExit(f"Не найден файл {INDEX_PATH}")

    logger.info("Панель: http://%s:%s", HOST, PORT)
    logger.info("Наблюдаемый HTTP-адрес: /probe")

    if SURICATA_EVE:
        logger.info("Источник Suricata: %s", SURICATA_EVE)

    # Отдельный access_log выключен:
    # события целевых HTTP-обработчиков регистрирует Monitor.
    web.run_app(
        create_app(),
        host=HOST,
        port=PORT,
        access_log=None,
    )
