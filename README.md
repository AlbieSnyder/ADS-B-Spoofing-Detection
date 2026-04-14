# ADS-B Spoofing & Replay Detection

**CSEC-569/669: Wireless Security — Aviation RF Signaling Security Project**

A receiver-side detection system that identifies spoofed and replayed ADS-B messages by combining GPS-based geometry validation, trajectory continuity analysis, and time-of-arrival freshness checks. Built to work with [dump1090]([https://github.com/antirez/dump1090](https://github.com/itemir/dump1090_sdrplus)) and two HackRF One SDRs for live demonstration in an isolated lab environment.

## Overview

Automatic Dependent Surveillance-Broadcast (ADS-B) operates over the Mode S protocol at 1090 MHz. Because Mode S packets lack cryptographic authentication, the protocol is vulnerable to physical-layer attacks including ghost-aircraft injection and message replay. This project demonstrates those vulnerabilities and implements lightweight receiver-side countermeasures.

The detection system applies three validation layers to every incoming ADS-B position report:

1. **GPS-Based Geometry Sanity Check** — Validates coordinate bounds, altitude plausibility, range from receiver, and radio line-of-sight using the 4/3 earth refraction model.
2. **Trajectory Continuity Validation** — Checks implied speed from position deltas, acceleration between reports, altitude rate of change, heading change rate, and cross-validates reported vs. implied ground speed.
3. **Time-of-Arrival Freshness Validation** — Detects duplicate messages, message bursts exceeding the nominal ~2 msg/s rate, replay gaps, and irregular update cadence.

Each check contributes a weighted score to a per-aircraft anomaly counter. When the cumulative score crosses a threshold (default 50), the track is flagged as **SPOOFED**.

## Repository Structure

```
├── adsb_spoof_detector.py    # Main detection engine (connects to dump1090)
├── sbs_parser.py             # SBS BaseStation message parser + PositionReport dataclass
├── geolocation.py            # Auto-detect receiver coordinates via IP geolocation
├── demo_traffic_gen.py       # Generates IQ sample files for HackRF transmission
├── updatedADSBEncoder.py     # ADS-B Mode S encoder (CPR encoding, CRC, PPM modulation)
└── README.md
```

## Requirements

- Python 3.9+
- [dump1090](https://github.com/antirez/dump1090) (for receiving ADS-B)
- Two [HackRF One](https://greatscottgadgets.com/hackrf/) SDRs (one for TX, one for RX)

### Python Dependencies

```bash
pip install geopy numpy
```

- `geopy` — WGS-84 geodesic distance calculations (used by the detector)
- `numpy` — bit packing for IQ sample generation (used by the encoder)

## Usage

### Receiver Side (RX Machine)

Start dump1090 and the detector in separate terminals:

```bash
# Terminal 1 — start dump1090
./dump1090 --net --interactive

# Terminal 2 — start the detector (auto-detects location via IP)
python3 adsb_spoof_detector.py

# Or specify coordinates manually
python3 adsb_spoof_detector.py --lat 43.0846 --lon -77.6743
```

The detector connects to dump1090's SBS output on port 30003, processes messages in real time, and prints a status summary every 15 seconds. Tracks that exceed the anomaly threshold are logged with the specific checks that triggered.

#### Detector Options

| Flag | Description |
|------|-------------|
| `--lat` / `--lon` | Receiver coordinates (auto-detected if omitted) |
| `--alt` | Receiver altitude in feet MSL (default: 0) |
| `--host` | dump1090 host (default: 127.0.0.1) |
| `--port` | dump1090 SBS port (default: 30003) |
| `--file` | Process a recorded SBS file instead of live input |
| `--json` | Output final summary as JSON |
| `-v` | Verbose (DEBUG) logging |

### Transmitter Side (TX Machine)

Generate IQ sample files for each attack scenario:

```bash
# Generate all scenarios (auto-detects location)
python3 demo_traffic_gen.py

# Or with explicit coordinates
python3 demo_traffic_gen.py --lat 43.0846 --lon -77.6743

# Generate a single scenario
python3 demo_traffic_gen.py --scenario ghost

# List available scenarios
python3 demo_traffic_gen.py --list
```

Transmit a scenario file with HackRF:

```bash
hackrf_transfer -t demo_samples/02_ghost_aircraft.iq8s -f 1090000000 -s 2000000 -x 40
```

### Demo Scenarios

| # | File | Description | Expected Result |
|---|------|-------------|-----------------|
| 1 | `01_legitimate.iq8s` | Normal flight — smooth trajectory at FL350, 450kt | CLEAN |
| 2 | `02_ghost_aircraft.iq8s` | Ghost injection — normal flight then 100+ NM position jump | SPOOFED |
| 3 | `03_replay_attack.iq8s` | Replay — same position repeated 30 times rapidly | SPOOFED |
| 4 | `04_impossible_params.iq8s` | Impossible parameters — altitude oscillates 55,000/5,000 ft | SPOOFED |
| 5 | `05_beyond_los.iq8s` | Beyond line-of-sight — low altitude, ~250 NM from receiver | SPOOFED |

## Detection Thresholds

All thresholds are defined as constants at the top of `adsb_spoof_detector.py` and can be tuned:

| Threshold | Default | Description |
|-----------|---------|-------------|
| `MAX_RANGE_NM` | 250 | Maximum plausible reception range (NM) |
| `MAX_ALTITUDE_FT` | 60,000 | Maximum plausible altitude (feet) |
| `MAX_SPEED_KT` | 700 | Maximum plausible ground speed (knots) |
| `MAX_ACCEL_KT_PER_S` | 15 | Maximum acceleration (knots/second) |
| `MAX_ALT_RATE_FPM` | 8,000 | Maximum climb/descent rate (feet/minute) |
| `MAX_HEADING_RATE_DEG_S` | 6.0 | Maximum heading change rate (°/second) |
| `MIN_INTER_ARRIVAL_S` | 0.05 | Below this interval → likely duplicate |
| `ALERT_THRESHOLD` | 50 | Cumulative anomaly score to flag as SPOOFED |

## Regulatory & Safety Warning

- **Receiving** ADS-B signals is legal.
- **Transmitting** spoofed or replayed ADS-B data over the air is a **federal offense**.

## References

1. Costin & Francillon, "Ghost in the Air (Traffic): On insecurity of ADS-B protocol and practical attacks on ADS-B devices," Black Hat USA, 2012.
2. Longo et al., "On a Collision Course: Unveiling Wireless Attacks to the Aircraft Traffic Collision Avoidance System (TCAS)," USENIX Security, 2024.
3. Rudys et al., "Physical layer protection for ADS-B against spoofing and jamming," Int. J. Critical Infrastructure Protection, vol. 38, 2022.
4. Zhang et al., "A robust and practical solution to ADS-B security against denial-of-service attacks," IEEE IoT Journal, vol. 11, no. 8, 2024.
5. Longo et al., "Unknown Target: Uncovering and Detecting Novel In-Flight Attacks to Collision Avoidance (TCAS)," NDSS Symposium, 2026.
6. Khan et al., "A Survey on Security of Automatic Dependent Surveillance-Broadcast (ADS-B) Protocol," IEEE COMST, vol. 27, no. 5, 2025.
