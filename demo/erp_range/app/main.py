"""Disposable university ERP range service.

The database contains GENERATED FICTIONAL data, never campus ERP data.
All health data comes from actual probes and process measurements.
"""
from __future__ import annotations

import os
import time

import psycopg
import psutil
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

SERVICE = "MON SYNTHETIC ERP — NO REAL STUDENT DATA"
DATABASE_URL = os.getenv("ERP_DATABASE_URL", "")
app = FastAPI(title=SERVICE, docs_url="/docs", redoc_url=None)

requests_total = Counter(
    "mon_erp_http_requests_total", "Real requests handled by synthetic ERP",
    ["route", "method", "status"],
)
request_duration = Histogram(
    "mon_erp_http_request_duration_seconds",
    "Actual synthetic ERP request duration",
    ["route", "method"],
)
db_probes = Counter(
    "mon_erp_database_probe_total",
    "Database probe results, observed rather than simulated", ["result"],
)
_process = psutil.Process()
process_rss_bytes = Gauge("mon_erp_process_rss_bytes", "Measured ERP process RSS")
process_cpu_seconds = Gauge(
    "mon_erp_process_cpu_seconds", "Measured ERP process CPU seconds"
)


def database_query(query: str, params: tuple[object, ...] = ()) -> list[tuple]:
    """Bounded, parameterized reads against disposable ERP database."""
    if not DATABASE_URL:
        raise RuntimeError("ERP database is not configured")
    with psycopg.connect(DATABASE_URL, connect_timeout=2) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SET statement_timeout TO 3000")
            cursor.execute(query, params)
            return cursor.fetchall()


@app.middleware("http")
async def measure(request: Request, call_next):
    started = time.monotonic()
    status = 500
    route = "unmatched"
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        # The routing layer assigns the path template to avoid unbounded metric
        # cardinality and exposure of user-controlled URL components.
        selected = request.scope.get("route")
        if selected is not None:
            route = getattr(selected, "path", "unmatched")
        requests_total.labels(route, request.method, str(status)).inc()
        request_duration.labels(route, request.method).observe(
            time.monotonic() - started
        )


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"state": "RUNNING", "service": SERVICE, "environment": "isolated-range"}


@app.get("/health/ready")
def ready() -> dict[str, str]:
    try:
        count = database_query("SELECT count(*) FROM synthetic_students")
    except (psycopg.Error, RuntimeError):
        db_probes.labels("failed").inc()
        raise HTTPException(status_code=503, detail="Synthetic ERP database unavailable") from None
    db_probes.labels("success").inc()
    return {
        "state": "READY",
        "service": SERVICE,
        "database": "RESPONDING",
        "synthetic_records": str(count[0][0]),
    }


@app.get("/api/students")
def students(limit: int = Query(default=10, ge=1, le=50)) -> dict[str, object]:
    try:
        rows = database_query(
            "SELECT student_code, display_name, programme "
            "FROM synthetic_students ORDER BY student_code LIMIT %s", (limit,),
        )
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail="Synthetic ERP database unavailable") from None
    return {
        "dataset": "FICTIONAL / GENERATED TEST RECORDS",
        "records": [
            {"code": code, "name": name, "programme": course}
            for code, name, course in rows
        ],
    }


@app.get("/api/record/{student_code}")
def record(student_code: str) -> dict[str, object]:
    if not student_code.startswith("DEMO-") or len(student_code) > 16:
        raise HTTPException(status_code=404, detail="Test record not found")
    try:
        rows = database_query(
            "SELECT student_code, display_name, programme "
            "FROM synthetic_students WHERE student_code = %s",
            (student_code,),
        )
    except (psycopg.Error, RuntimeError):
        raise HTTPException(status_code=503, detail="Synthetic ERP database unavailable") from None
    if not rows:
        raise HTTPException(status_code=404, detail="Test record not found")
    code, name, course = rows[0]
    return {
        "dataset": "FICTIONAL", "code": code,
        "name": name, "programme": course,
    }


@app.get("/metrics")
def metrics() -> Response:
    with _process.oneshot():
        rss = _process.memory_info().rss
        cpu = _process.cpu_times()
    # Process-local data only; PC4 host CPU/RAM requires independent host exporter.
    process_rss_bytes.set(float(rss))
    process_cpu_seconds.set(cpu.user + cpu.system)
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
