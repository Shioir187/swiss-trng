# 🇨🇭 SwissTRNG

> A physical true random number generator powered by artificial snow swirling over a 3D-printed Swiss mountain.

Snow is whirled by PWM fans over a 3D-printed Alpine massif, captured every 60 s by a Raspberry Pi HQ camera, hashed (SHA-256) into a 32-byte seed, and served as signed pulses through a NIST IR 8213 v2.0 beacon (subset) on a Flask REST API.

Developed as part of the **IIP2 module at HSLU Informatik (FS26)**.

## Results

NIST SP 800-90B Entropy Assessment (Non-IID): **7.09 bit/byte** min-entropy — placing the source in the range of commercially evaluated TRNGs. The snow contributes +0.37 bit/byte over the bare sensor noise, mainly by breaking the Fixed-Pattern-Noise correlation between frames.

## Files

| File              | Purpose                                                        |
| ----------------- | -------------------------------------------------------------- |
| `Mountain_RNG.py` | Camera loop, seed refresh, Shannon monitor, fan control        |
| `beacon.py`       | NIST IR 8213 beacon, SQLite, Flask REST API on `:8080`         |
| `beacon_setup.py` | One-time RSA-4096 key + self-signed certificate generation     |

## Setup

```bash
sudo apt install python3-venv pigpio && sudo systemctl enable --now pigpiod
python3 -m venv .venv && source .venv/bin/activate
pip install requests numpy rawpy pigpio flask cryptography

python3 beacon_setup.py                   # one-time
export GRAFANA_USER="…" GRAFANA_TOKEN="…" # never commit these
sudo systemctl enable --now mountain-rng.service mountain-beacon.service
```

## API

```
GET /beacon/2.0/pulse/last        most recent signed pulse
GET /beacon/2.0/pulse/<id>        specific pulse by index
GET /docs                         interactive Swagger UI
```

## ⚠️ Disclaimer

Student project, not a certified production RNG. Beacon uses a self-signed cert under a placeholder URI. Per NIST IR 8213, pulse values are public and **must not be used as secret keys** — only as a publicly verifiable randomness source.
