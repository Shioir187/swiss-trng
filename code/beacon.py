#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NIST IR 8213 v2.0 Beacon - Mountain RNG

Erzeugt jede Minute einen Pulse mit:
  - 21 Pflichtfelder gem. IR 8213
  - Hash-Chain: previous, hour, day, month, year
  - Pre-Commitment: Pulse N enthaelt hash(localRandomValue_{N+1})
  - RSA-4096 + SHA-512 Signatur (cipherSuite=0)
  - Optional: externe Entropie aus offizieller NIST-Beacon

REST-API:
  GET /                                  Beschreibung
  GET /docs                              Swagger UI
  GET /openapi.json                      OpenAPI 3.0 Spezifikation
  GET /beacon/2.0/pulse/last             letzter Pulse
  GET /beacon/2.0/pulse/<id>             Pulse per pulseIndex
  GET /beacon/2.0/chain/1/pulse/<id>     gleiches (Spec-Pfad)
  GET /beacon/2.0/certificate/<id>       Zertifikat als PEM
"""

import os
import sys
import json
import time
import struct
import hashlib
import sqlite3
import threading
import logging
import traceback
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, abort, Response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# =============================================================================
# KONFIGURATION
# =============================================================================

BASE_DIR     = "/home/iip/mountain-rng/beacon/"
DB_PATH      = os.path.join(BASE_DIR, "beacon.db")
PRIV_PATH    = os.path.join(BASE_DIR, "beacon_priv.pem")
CERT_PATH    = os.path.join(BASE_DIR, "beacon_cert.pem")
CERTID_PATH  = os.path.join(BASE_DIR, "certificateId.txt")

SEED_FILE    = "/home/iip/mountain-rng/current_seed.bin"

URI_PREFIX   = "https://beacon.local/beacon/2.0"
VERSION_STR  = "2.0"
CIPHER_SUITE = 0
CHAIN_INDEX  = 1
PERIOD_MS    = 60_000

USE_EXTERNAL_ENTROPY = True
NIST_BEACON_URL      = "https://beacon.nist.gov/beacon/2.0/pulse/last"

API_HOST     = "0.0.0.0"
API_PORT     = 8080

BLEN_HASH    = 64
ZERO_HASH    = b"\x00" * BLEN_HASH

FLS_RNDLOC   = 0x01
FLS_GAP      = 0x02
FLS_CERTID   = 0x04
FLS_END      = 0x08


# =============================================================================
# BYTE-SERIALISIERUNG (gem. IR 8213 Sec. 4.1.2)
# =============================================================================

def ser_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">Q", len(b)) + b


def ser_hash(h: bytes) -> bytes:
    assert len(h) == BLEN_HASH, f"hash muss {BLEN_HASH} bytes sein"
    return struct.pack(">Q", BLEN_HASH) + h


def ser_sig(s: bytes) -> bytes:
    return struct.pack(">Q", len(s)) + s


def ser_uint32(v: int) -> bytes:
    return struct.pack(">I", v)


def ser_uint64(v: int) -> bytes:
    return struct.pack(">Q", v)


def serialize_signed_fields(p: dict) -> bytes:
    return b"".join([
        ser_string(p["uri"]),
        ser_string(p["version"]),
        ser_uint32(p["cipherSuite"]),
        ser_uint32(p["period"]),
        ser_hash(p["certificateId"]),
        ser_uint64(p["chainIndex"]),
        ser_uint64(p["pulseIndex"]),
        ser_string(p["timeStamp"]),
        ser_hash(p["localRandomValue"]),
        ser_hash(p["external_sourceId"]),
        ser_uint64(p["external_statusCode"]),
        ser_hash(p["external_value"]),
        ser_hash(p["previous"]),
        ser_hash(p["hour"]),
        ser_hash(p["day"]),
        ser_hash(p["month"]),
        ser_hash(p["year"]),
        ser_hash(p["precommitmentValue"]),
        ser_uint32(p["statusCode"]),
    ])


def serialize_output_input(p: dict) -> bytes:
    return serialize_signed_fields(p) + ser_sig(p["signatureValue"])


# =============================================================================
# DATABASE
# =============================================================================

def db_init():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pulses (
            pulseIndex     INTEGER PRIMARY KEY,
            timeStamp      TEXT    UNIQUE NOT NULL,
            timeStamp_unix INTEGER NOT NULL,
            pulse_json     TEXT    NOT NULL,
            outputValue    BLOB    NOT NULL,
            localRandomValue BLOB  NOT NULL,
            next_randLocal BLOB    NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_unix ON pulses(timeStamp_unix)")
    conn.commit()
    return conn


def db_get_pulse(conn, pulse_index: int):
    row = conn.execute(
        "SELECT pulse_json FROM pulses WHERE pulseIndex = ?",
        (pulse_index,)).fetchone()
    return json.loads(row[0]) if row else None


def db_last_pulse(conn):
    row = conn.execute(
        "SELECT pulse_json FROM pulses ORDER BY pulseIndex DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None


def db_last_row(conn):
    return conn.execute(
        "SELECT pulseIndex, outputValue, localRandomValue, next_randLocal, "
        "timeStamp, timeStamp_unix "
        "FROM pulses ORDER BY pulseIndex DESC LIMIT 1").fetchone()


def db_first_pulse_after(conn, unix_ts: int):
    row = conn.execute(
        "SELECT outputValue FROM pulses WHERE timeStamp_unix >= ? "
        "ORDER BY timeStamp_unix ASC LIMIT 1", (unix_ts,)).fetchone()
    return bytes(row[0]) if row else None


# =============================================================================
# KRYPTO
# =============================================================================

def load_private_key():
    with open(PRIV_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cert_id() -> bytes:
    with open(CERTID_PATH) as f:
        return bytes.fromhex(f.read().strip())


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def rsa_sign(priv, message: bytes) -> bytes:
    return priv.sign(message, padding.PKCS1v15(), hashes.SHA512())


# =============================================================================
# QUELLEN: randLocal + external entropy
# =============================================================================

def sample_rand_local() -> bytes:
    try:
        with open(SEED_FILE, "rb") as f:
            rng1 = f.read()[:32]
    except FileNotFoundError:
        rng1 = b"\x00" * 32

    rng2 = os.urandom(64)
    rng3 = struct.pack(">Q", time.time_ns())

    return sha512(rng1 + rng2 + rng3)


def fetch_external_entropy():
    if not USE_EXTERNAL_ENTROPY:
        return ZERO_HASH, 1, ZERO_HASH

    try:
        r = requests.get(NIST_BEACON_URL, timeout=3)
        r.raise_for_status()
        ext_pulse = r.json()["pulse"]
        source_id = sha512(NIST_BEACON_URL.encode("utf-8"))
        value = bytes.fromhex(ext_pulse["outputValue"])
        if len(value) != BLEN_HASH:
            print(f"[EXT] NIST-Beacon: unerwartete Hash-Laenge {len(value)}")
            return ZERO_HASH, 1, ZERO_HASH
        return source_id, 0, value
    except Exception as e:
        print(f"[EXT] NIST-Beacon nicht erreichbar: {e}")
        return ZERO_HASH, 1, ZERO_HASH


# =============================================================================
# PULSE-ERZEUGUNG
# =============================================================================

def build_uri(pulse_index: int) -> str:
    return f"{URI_PREFIX}/chain/{CHAIN_INDEX}/pulse/{pulse_index}"


def utc_timestamp_str(unix_ts: int) -> str:
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def first_of(unix_ts: int, unit: str) -> int:
    dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    if unit == "hour":
        return int(dt.replace(minute=0, second=0, microsecond=0).timestamp())
    if unit == "day":
        return int(dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    if unit == "month":
        return int(dt.replace(day=1, hour=0, minute=0, second=0,
                              microsecond=0).timestamp())
    if unit == "year":
        return int(dt.replace(month=1, day=1, hour=0, minute=0, second=0,
                              microsecond=0).timestamp())
    raise ValueError(unit)


def generate_pulse(conn, priv, cert_id: bytes,
                   unix_ts: int,
                   this_rand_local: bytes,
                   next_rand_local: bytes) -> dict:
    prev_row = db_last_row(conn)
    ext_source, ext_status, ext_value = fetch_external_entropy()

    if prev_row is None:
        pulse_index = 1
        previous = ZERO_HASH
        status   = FLS_RNDLOC
    else:
        pulse_index = prev_row[0] + 1
        previous    = bytes(prev_row[1])
        prev_unix   = prev_row[5]
        expected = prev_unix + PERIOD_MS // 1000
        status = 0 if unix_ts == expected else FLS_GAP

    if pulse_index == 1:
        hour_h = day_h = month_h = year_h = ZERO_HASH
    else:
        prev_unix = prev_row[5]
        hour_h  = db_first_pulse_after(conn, first_of(prev_unix, "hour"))  or ZERO_HASH
        day_h   = db_first_pulse_after(conn, first_of(prev_unix, "day"))   or ZERO_HASH
        month_h = db_first_pulse_after(conn, first_of(prev_unix, "month")) or ZERO_HASH
        year_h  = db_first_pulse_after(conn, first_of(prev_unix, "year"))  or ZERO_HASH

    pulse = {
        "uri":                  build_uri(pulse_index),
        "version":              VERSION_STR,
        "cipherSuite":          CIPHER_SUITE,
        "period":               PERIOD_MS,
        "certificateId":        cert_id,
        "chainIndex":           CHAIN_INDEX,
        "pulseIndex":           pulse_index,
        "timeStamp":            utc_timestamp_str(unix_ts),
        "localRandomValue":     this_rand_local,
        "external_sourceId":    ext_source,
        "external_statusCode":  ext_status,
        "external_value":       ext_value,
        "previous":             previous,
        "hour":                 hour_h,
        "day":                  day_h,
        "month":                month_h,
        "year":                 year_h,
        "precommitmentValue":   sha512(next_rand_local),
        "statusCode":           status,
    }

    sig_input  = serialize_signed_fields(pulse)
    pulse["signatureValue"] = rsa_sign(priv, sig_input)
    pulse["outputValue"] = sha512(serialize_output_input(pulse))

    return pulse


def pulse_to_json(p: dict) -> dict:
    out = {}
    for k, v in p.items():
        if isinstance(v, bytes):
            out[k] = v.hex().upper()
        else:
            out[k] = v
    return out


def store_pulse(conn, pulse: dict, next_rand_local: bytes):
    pj = pulse_to_json(pulse)
    unix_ts = int(datetime.strptime(
        pulse["timeStamp"], "%Y-%m-%dT%H:%M:%S.000Z"
    ).replace(tzinfo=timezone.utc).timestamp())

    conn.execute(
        "INSERT INTO pulses (pulseIndex, timeStamp, timeStamp_unix, pulse_json, "
        "outputValue, localRandomValue, next_randLocal) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (pulse["pulseIndex"], pulse["timeStamp"], unix_ts,
         json.dumps(pj),
         pulse["outputValue"], pulse["localRandomValue"], next_rand_local))
    conn.commit()


# =============================================================================
# BEACON-LOOP
# =============================================================================

stop_event = threading.Event()


def beacon_loop():
    print("[BEACON] Loop gestartet")
    conn    = db_init()
    priv    = load_private_key()
    cert_id = load_cert_id()

    while not stop_event.is_set():
        now = time.time()
        next_slot = int((now // 60 + 1) * 60)
        wait = next_slot - now
        if wait > 0:
            if stop_event.wait(wait):
                break

        try:
            last = db_last_row(conn)
            if last is None:
                this_rand_local = sample_rand_local()
            else:
                this_rand_local = bytes(last[3])

            next_rand_local = sample_rand_local()
            pulse = generate_pulse(conn, priv, cert_id,
                                   next_slot, this_rand_local, next_rand_local)
            store_pulse(conn, pulse, next_rand_local)

            print(f"[BEACON] Pulse #{pulse['pulseIndex']} @ {pulse['timeStamp']} "
                  f"out={pulse['outputValue'].hex()[:16]}...")
        except Exception as e:
            print(f"[BEACON] FEHLER bei Pulse-Generierung: {e}")
            traceback.print_exc()


# =============================================================================
# FLASK API
# =============================================================================

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@app.route("/")
def root():
    return jsonify({
        "name":        "Mountain RNG Beacon",
        "spec":        "NIST IR 8213 v2.0 (subset)",
        "chainIndex":  CHAIN_INDEX,
        "period_ms":   PERIOD_MS,
        "external_entropy": "NIST official beacon" if USE_EXTERNAL_ENTROPY else "none",
        "endpoints": {
            "/docs":                              "Swagger UI",
            "/openapi.json":                      "OpenAPI 3.0 Spec",
            "/beacon/2.0/pulse/last":             "letzter Pulse",
            "/beacon/2.0/pulse/<id>":             "Pulse per pulseIndex",
            "/beacon/2.0/chain/1/pulse/<id>":     "gleicher Pulse (Spec-Pfad)",
            "/beacon/2.0/certificate/<id>":       "Zertifikat (PEM)",
        }
    })


# =============================================================================
# OPENAPI / SWAGGER UI
# =============================================================================

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Mountain RNG Beacon",
        "description": "NIST IR 8213 v2.0 conformant Randomness Beacon. "
                       "Quelle: Pi HQ Camera + Schnee (Raw DNG). "
                       "NIST SP 800-90B Min-Entropie: 7.09 bit/byte.",
        "version": "2.0",
        "contact": {"name": "Mountain RNG"}
    },
    "servers": [
        {"url": "/", "description": "Diese Beacon"}
    ],
    "paths": {
        "/": {
            "get": {
                "summary": "Beacon-Beschreibung",
                "description": "Metadaten und verfuegbare Endpoints.",
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {"application/json": {}}
                    }
                }
            }
        },
        "/beacon/2.0/pulse/last": {
            "get": {
                "summary": "Letzter Pulse",
                "description": "Aktuellster signierter Pulse mit allen 21 IR-8213-Feldern.",
                "responses": {
                    "200": {
                        "description": "Pulse",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PulseResponse"}
                            }
                        }
                    },
                    "404": {"description": "Noch keine Pulses generiert"}
                }
            }
        },
        "/beacon/2.0/pulse/{pulseIndex}": {
            "get": {
                "summary": "Pulse per Index",
                "parameters": [{
                    "name": "pulseIndex",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "integer", "minimum": 1},
                    "example": 1
                }],
                "responses": {
                    "200": {"description": "Pulse"},
                    "404": {"description": "Pulse nicht gefunden"}
                }
            }
        },
        "/beacon/2.0/chain/1/pulse/{pulseIndex}": {
            "get": {
                "summary": "Pulse per Index (Spec-Pfad)",
                "parameters": [{
                    "name": "pulseIndex",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "integer", "minimum": 1}
                }],
                "responses": {"200": {"description": "Pulse"}}
            }
        },
        "/beacon/2.0/certificate/{certificateId}": {
            "get": {
                "summary": "X.509 Zertifikat als PEM",
                "parameters": [{
                    "name": "certificateId",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "SHA-512-Hash des Zertifikat-PEMs (Hex)"
                }],
                "responses": {
                    "200": {
                        "description": "PEM-Zertifikat",
                        "content": {"application/x-pem-file": {}}
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "PulseResponse": {
                "type": "object",
                "properties": {
                    "pulse": {"$ref": "#/components/schemas/Pulse"}
                }
            },
            "Pulse": {
                "type": "object",
                "description": "NIST IR 8213 v2.0 Pulse",
                "properties": {
                    "uri":                 {"type": "string"},
                    "version":             {"type": "string", "example": "2.0"},
                    "cipherSuite":         {"type": "integer", "example": 0},
                    "period":              {"type": "integer", "example": 60000},
                    "certificateId":       {"type": "string", "description": "SHA-512 hex"},
                    "chainIndex":          {"type": "integer"},
                    "pulseIndex":          {"type": "integer"},
                    "timeStamp":           {"type": "string", "format": "date-time"},
                    "localRandomValue":    {"type": "string", "description": "512-bit hex"},
                    "external_sourceId":   {"type": "string"},
                    "external_statusCode": {"type": "integer"},
                    "external_value":      {"type": "string"},
                    "previous":            {"type": "string"},
                    "hour":                {"type": "string"},
                    "day":                 {"type": "string"},
                    "month":               {"type": "string"},
                    "year":                {"type": "string"},
                    "precommitmentValue":  {"type": "string"},
                    "statusCode":          {"type": "integer"},
                    "signatureValue":      {"type": "string", "description": "RSA-Signatur hex"},
                    "outputValue":         {"type": "string", "description": "SHA-512 hex"}
                }
            }
        }
    }
}


SWAGGER_UI_HTML = """<!DOCTYPE html>
<html>
<head>
  <title>Mountain RNG Beacon - API Docs</title>
  <link rel="stylesheet" type="text/css"
        href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui.css">
  <style>body{margin:0;}</style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = () => {
      SwaggerUIBundle({
        url: "/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout",
      });
    };
  </script>
</body>
</html>"""


@app.route("/openapi.json")
def openapi_spec():
    return jsonify(OPENAPI_SPEC)


@app.route("/docs")
def swagger_ui():
    return Response(SWAGGER_UI_HTML, mimetype="text/html")


# =============================================================================
# BEACON-ENDPOINTS
# =============================================================================

@app.route("/beacon/2.0/pulse/last")
def pulse_last():
    p = db_last_pulse(get_conn())
    if not p:
        abort(404, "no pulses yet")
    return jsonify({"pulse": p})


@app.route("/beacon/2.0/pulse/<int:pid>")
@app.route("/beacon/2.0/chain/1/pulse/<int:pid>")
def pulse_by_id(pid):
    p = db_get_pulse(get_conn(), pid)
    if not p:
        abort(404, f"pulse {pid} not found")
    return jsonify({"pulse": p})


@app.route("/beacon/2.0/certificate/<cid>")
def certificate(cid):
    expected = load_cert_id().hex().upper()
    if cid.upper() != expected:
        abort(404, "unknown certificate id")
    with open(CERT_PATH, "rb") as f:
        return Response(f.read(), mimetype="application/x-pem-file")


def api_server():
    print(f"[API] Beacon-API auf http://{API_HOST}:{API_PORT}")
    print(f"[API] Swagger UI auf http://{API_HOST}:{API_PORT}/docs")
    app.run(host=API_HOST, port=API_PORT, threaded=True,
            use_reloader=False, debug=False)


# =============================================================================
# MAIN
# =============================================================================

def main():
    if not os.path.exists(PRIV_PATH):
        print("FEHLER: Erst 'python3 beacon_setup.py' ausfuehren.")
        sys.exit(1)

    print("=" * 50)
    print("    NIST IR 8213 Beacon - Mountain RNG")
    print("=" * 50)
    print(f"Periode      : {PERIOD_MS} ms  ({PERIOD_MS/1000:.0f}s)")
    print(f"Chain        : {CHAIN_INDEX}")
    print(f"URI          : {URI_PREFIX}")
    print(f"DB           : {DB_PATH}")
    print(f"External ent.: {'NIST beacon' if USE_EXTERNAL_ENTROPY else 'aus'}")
    print("-" * 50)

    threads = [
        threading.Thread(target=beacon_loop, name="beacon", daemon=True),
        threading.Thread(target=api_server,  name="api",    daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[BEACON] Beende...")
        stop_event.set()
        for t in threads:
            t.join(timeout=3)


if __name__ == "__main__":
    main()