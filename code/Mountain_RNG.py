#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mountain RNG - kombiniertes Steuerskript

Vereint vier urspruengliche Skripte in einem Prozess:
  1. Kamera-Loop       -> alle 60 s ein DNG-Rohbild
  2. Seed-Refresh      -> hasht das aktuelle Bild zu einem 32-Byte-Seed
  3. Shannon-Monitor   -> Shannon-Entropie der raw Noise Source (pre-conditioning)
  4. Output-Loop       -> alle 5 s ein RNG-Sample + Push nach Grafana / Loki
  5. Luefter-Steuerung -> Taster + Tastatur

An Grafana wird gesendet:
  - conditioned_output     SHA-256(seed||time) erste 32 Bit als Integer
  - noise_source_shannon   Shannon-Entropie der Quelle in bit/byte
"""

import os
import sys
import time
import signal
import hashlib
import threading
import subprocess

import requests
import pigpio
import numpy as np
import rawpy


# =============================================================================
# KONFIGURATION
# =============================================================================

BASE_DIR     = "/home/iip/mountain-rng/"
FINAL_DNG    = os.path.join(BASE_DIR, "aktuell.dng")
SEED_FILE    = os.path.join(BASE_DIR, "current_seed.bin")

CAMERA_INTERVAL = 60
OUTPUT_INTERVAL = 5

GRAFANA_URL   = "https://logs-prod-039.grafana.net/loki/api/v1/push"
GRAFANA_USER  = "1543986"
GRAFANA_TOKEN = "glc_eyJvIjoiMTcyNDEyMyIsIm4iOiJlbnRyb3B5LXBpLXBpX2dyYWZhbmFfYXBpIiwiayI6IlNWbkNINjVjNDQ1SXc0M0wwWWg3VkY5WCIsIm0iOnsiciI6InByb2QtZXUtY2VudHJhbC0wIn19"

FAN_PIN        = 18
BUTTON_PIN     = 27
MODE_POWER_DC  = 80
MODE_POWER_HZ  = 300
MODE_NORMAL_DC = 50
MODE_NORMAL_HZ = 4000

CAMERA_CMD_BASE = [
    "rpicam-still",
    "-n",
    "--raw",
    "--encoding", "yuv420",
    "--shutter", "2000",
    "--gain", "1.0",
    "--awbgains", "1,1",
    "--denoise", "off",
    "--sharpness", "0",
    "--contrast", "1",
    "--brightness", "0",
    "--saturation", "1",
    "--exif", "none",
    "--immediate",
    "--timeout", "500",
]


# =============================================================================
# GLOBALER ZUSTAND
# =============================================================================

stop_event              = threading.Event()
shannon_lock            = threading.Lock()
latest_shannon_entropy  = 0.0
pi                      = None


# =============================================================================
# SHANNON-ENTROPIE DER RAW NOISE SOURCE
# =============================================================================

def calculate_raw_shannon_entropy(dng_path):
    """
    Shannon-Entropie der raw Noise Source (pre-conditioning).
    Pipeline identisch zum NIST SP 800-90B Test:
        DNG -> G1-Bayer -> Saturation-Filter -> lower 4 bits -> pack to bytes -> H
    Rueckgabe: float in [0, 8] bit/byte, oder None.
    """
    try:
        with rawpy.imread(dng_path) as raw:
            img = raw.raw_image.copy()
    except Exception as e:
        print(f"[SHANNON] rawpy Fehler: {e}")
        return None

    max_val = int(img.max())
    if max_val == 0:
        return None

    g1 = img[0::2, 1::2].flatten()
    g1 = g1[g1 != max_val]
    if len(g1) < 1000:
        return None

    lsb4 = (g1 & 0xF).astype(np.uint8)
    n_pairs = len(lsb4) // 2
    bytes_arr = (lsb4[0:2*n_pairs:2] << 4) | lsb4[1:2*n_pairs:2]

    counts = np.bincount(bytes_arr, minlength=256).astype(np.float64)
    probs  = counts[counts > 0] / counts.sum()
    return float(-np.sum(probs * np.log2(probs)))


def update_shannon_from_current_dng():
    global latest_shannon_entropy
    shannon = calculate_raw_shannon_entropy(FINAL_DNG)
    if shannon is not None:
        with shannon_lock:
            latest_shannon_entropy = shannon
        print(f"[SHANNON] Raw Quelle: {shannon:.4f} bit/byte (max 8.00)")


# =============================================================================
# KAMERA-LOOP
# =============================================================================

def camera_loop():
    print("[CAM] Kamera-Loop gestartet")
    while not stop_event.is_set():
        dummy_jpg = FINAL_DNG.replace(".dng", ".jpg")
        cmd = CAMERA_CMD_BASE + ["-o", dummy_jpg]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            print("[CAM] Timeout - rpicam-still haengt")
            stop_event.wait(CAMERA_INTERVAL)
            continue

        if result.returncode == 0:
            try:
                produced_dng = dummy_jpg.replace(".jpg", ".dng")
                if not os.path.exists(produced_dng):
                    folder = os.path.dirname(FINAL_DNG)
                    candidates = [f for f in os.listdir(folder) if f.endswith(".dng")]
                    if candidates:
                        produced_dng = os.path.join(folder, candidates[0])

                if os.path.exists(produced_dng) and produced_dng != FINAL_DNG:
                    os.replace(produced_dng, FINAL_DNG)
                if os.path.exists(dummy_jpg):
                    os.remove(dummy_jpg)

                print(f"[CAM] [{time.strftime('%H:%M:%S')}] DNG gespeichert")
                refresh_seed()
                update_shannon_from_current_dng()
            except Exception as e:
                print(f"[CAM] Bildverarbeitungsfehler: {e}")
        else:
            print(f"[CAM] Kamera-Fehler: {result.stderr.strip()}")

        stop_event.wait(CAMERA_INTERVAL)


# =============================================================================
# SEED-REFRESH
# =============================================================================

def refresh_seed():
    if not os.path.exists(FINAL_DNG):
        return
    try:
        with open(FINAL_DNG, "rb") as f:
            img_data = f.read()
        system_noise = os.urandom(32)
        new_seed = hashlib.sha256(img_data + system_noise).digest()
        tmp = SEED_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(new_seed)
        os.rename(tmp, SEED_FILE)
        print(f"[SEED] Neuer Seed: {new_seed.hex()[:16]}...")
    except Exception as e:
        print(f"[SEED] Fehler: {e}")


# =============================================================================
# OUTPUT-LOOP
# =============================================================================

def get_mountain_data():
    """Liest 32-Byte-Seed aus current_seed.bin."""
    try:
        with open(SEED_FILE, "rb") as f:
            data = f.read()
            return data[:32]
    except FileNotFoundError:
        return os.urandom(32)


def send_to_grafana(conditioned_output, noise_source_shannon):
    now_ns = str(int(time.time() * 1_000_000_000))
    payload = {
        "streams": [{
            "stream": {"job": "entropy_pi"},
            "values": [[now_ns,
                        f"conditioned_output={conditioned_output} "
                        f"noise_source_shannon={noise_source_shannon:.4f}"]]
        }]
    }
    try:
        r = requests.post(GRAFANA_URL, json=payload,
                          auth=(GRAFANA_USER, GRAFANA_TOKEN), timeout=5)
        if r.status_code != 204:
            print(f"[GRAFANA] Fehler {r.status_code}: {r.text}")
    except requests.RequestException as e:
        print(f"[GRAFANA] Verbindung fehlgeschlagen: {e}")


def output_loop():
    print("[OUT] Output-Loop gestartet")
    while not stop_event.is_set():
        seed = get_mountain_data()

        final_hex = hashlib.sha256(seed + str(time.time()).encode()).hexdigest()
        conditioned_output = int(final_hex[:8], 16)

        with shannon_lock:
            shannon = latest_shannon_entropy

        print(f"[OUT] {final_hex}  "
              f"| out={conditioned_output:>10}  H={shannon:.4f}")

        send_to_grafana(conditioned_output, shannon)
        stop_event.wait(OUTPUT_INTERVAL)


# =============================================================================
# LUEFTER
# =============================================================================

def set_power():
    pi.hardware_PWM(FAN_PIN, MODE_POWER_HZ, MODE_POWER_DC * 10000)
    print(f"[FAN] POWER  ({MODE_POWER_DC}% @ {MODE_POWER_HZ} Hz)")


def set_normal():
    pi.hardware_PWM(FAN_PIN, MODE_NORMAL_HZ, MODE_NORMAL_DC * 10000)
    print(f"[FAN] NORMAL ({MODE_NORMAL_DC}% @ {MODE_NORMAL_HZ} Hz)")


def fan_off():
    pi.hardware_PWM(FAN_PIN, MODE_NORMAL_HZ, 0)
    print("[FAN] AUS")


def button_callback(gpio, level, tick):
    if level == 0:
        set_power()
    elif level == 1:
        set_normal()


# =============================================================================
# MAIN
# =============================================================================

def main():
    global pi
    pi = pigpio.pi()
    if not pi.connected:
        print("FEHLER: pigpiod laeuft nicht  ->  sudo systemctl start pigpiod")
        return

    pi.set_mode(BUTTON_PIN, pigpio.INPUT)
    pi.set_pull_up_down(BUTTON_PIN, pigpio.PUD_UP)
    cb = pi.callback(BUTTON_PIN, pigpio.EITHER_EDGE, button_callback)
    set_normal()

    print("=" * 50)
    print("        Mountain RNG - kombiniertes Skript v4")
    print("=" * 50)
    print(f"Luefter Power : {MODE_POWER_DC}% @ {MODE_POWER_HZ} Hz   (Taster halten)")
    print(f"Luefter Normal: {MODE_NORMAL_DC}% @ {MODE_NORMAL_HZ} Hz")
    print(f"Kamera alle {CAMERA_INTERVAL}s, Grafana-Push alle {OUTPUT_INTERVAL}s")
    print("Grafana-Felder: conditioned_output, noise_source_shannon")
    print("Tastatur: [p] Power, [n] Normal, [o] Aus, [q] Ende")
    print("-" * 50)

    if os.path.exists(FINAL_DNG):
        update_shannon_from_current_dng()

    threads = [
        threading.Thread(target=camera_loop, name="camera", daemon=True),
        threading.Thread(target=output_loop, name="output", daemon=True),
    ]
    for t in threads:
        t.start()

    # SIGTERM-Handler fuer sauberes Beenden als systemd-Service
    signal.signal(signal.SIGTERM, lambda sig, frame: stop_event.set())

    if sys.stdin.isatty():
        # Interaktiver Modus: Tastatureingabe aktiv
        try:
            while True:
                try:
                    auswahl = input().strip().lower()
                except EOFError:
                    break
                if auswahl == "p":
                    set_power()
                elif auswahl == "n":
                    set_normal()
                elif auswahl == "o":
                    fan_off()
                elif auswahl == "q":
                    break
                elif auswahl:
                    print("Ungueltige Eingabe. [p/n/o/q]")
        except KeyboardInterrupt:
            pass
    else:
        # Service-Modus: kein stdin, einfach warten bis stop_event gesetzt wird
        print("[SVC] Laeuft als Service - warte auf SIGTERM")
        stop_event.wait()

    print("\nBeende...")
    stop_event.set()
    try:
        pi.hardware_PWM(FAN_PIN, 0, 0)
        cb.cancel()
        pi.stop()
    except Exception:
        pass
    for t in threads:
        t.join(timeout=3)
    print("Programm beendet.")


if __name__ == "__main__":
    main()
