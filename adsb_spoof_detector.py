#!/usr/bin/env python3
import argparse
import json
import logging
import math
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from geopy.distance import geodesic


#  CONSTANTS

EARTH_RADIUS_KM = 6371.0
NM_TO_KM = 1.852
FT_TO_M = 0.3048
KT_TO_KMH = 1.852

# Detection thresholds (tunable)
MAX_RANGE_NM = 250 # max plausible reception range (NM)
MAX_ALTITUDE_FT = 60000 # max plausible altitude (feet)
MAX_SPEED_KT = 700 # max expected speed for commercial aircraft (knots)
MAX_ACCEL_KT_PER_S = 15 # max acceleration (knots/second)
MAX_ALT_RATE_FPM = 8000 # max altitude rate of change (feet/minute)
MAX_HEADING_RATE_DEG_S = 6.0 # max heading change rate (degrees/second)

# Time-of-arrival thresholds
EXPECTED_UPDATE_INTERVAL_S = 0.5 # normal ADS-B update interval
MIN_INTER_ARRIVAL_S = 0.05 # below this → likely duplicate
DUPLICATE_POSITION_THRESHOLD_NM = 0.01 # positions closer than this are "same"
MAX_REPLAY_STALENESS_S = 5.0 # message older than this is suspect
STALE_TRACK_TIMEOUT_S = 60.0 # drop track after this silence

# Scoring
ALERT_THRESHOLD = 50  #anomaly score needed to trigger an alert



#  DATA STRUCTURES

class AlertLevel(Enum):
    CLEAN = auto()
    SUSPICIOUS = auto()
    SPOOFED = auto()


from sbs_parser import PositionReport, parse_sbs_line
from geolocation import get_location


@dataclass
class AircraftTrack:
    """State maintained per tracked ICAO address."""
    icao: str
    reports: list[PositionReport] = field(default_factory=list)
    anomaly_score: float = 0.0
    alert_level: AlertLevel = AlertLevel.CLEAN
    anomaly_log: list[str] = field(default_factory=list)
    duplicate_count: int = 0
    last_update: float = 0.0

    def add_report(self, report: PositionReport):
        self.reports.append(report)
        self.last_update = report.timestamp
        # Keep a sliding window of the last 50 reports
        if len(self.reports) > 50:
            self.reports = self.reports[-50:]

    @property
    def prev(self) -> PositionReport | None:
        return self.reports[-2] if len(self.reports) >= 2 else None

    @property
    def current(self) -> PositionReport:
        return self.reports[-1]

    def flag(self, reason: str, score: float):
        self.anomaly_score += score
        entry = f"[score +{score:.0f} = {self.anomaly_score:.0f}] {reason}"
        self.anomaly_log.append(entry)
        if self.anomaly_score >= ALERT_THRESHOLD:
            self.alert_level = AlertLevel.SPOOFED
        elif self.anomaly_score >= ALERT_THRESHOLD * 0.5:
            self.alert_level = AlertLevel.SUSPICIOUS


#  GEOMETRY UTILITIES

def geodesic_nm(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """WGS-84 geodesic distance in NM"""
    return geodesic((lat1, lon1), (lat2, lon2)).nautical


def heading_diff(h1: float, h2: float) -> float:
    """Smallest signed angular difference between two headings."""
    d = (h2 - h1 + 180) % 360 - 180
    return d


def max_line_of_sight_nm(alt_ft: float, receiver_alt_ft: float = 0) -> float:
    """
    Approximate radio line-of-sight range given aircraft altitude and receiver altitude, using the 4/3 earth refraction model in NM.
    """
    alt_m = alt_ft * FT_TO_M
    rx_m = receiver_alt_ft * FT_TO_M
    return 1.23 * (math.sqrt(max(alt_ft, 0)) + math.sqrt(max(receiver_alt_ft, 0)))


#  DETECTION CHECKS

class SpoofDetector:
    """
    Maintains per-aircraft tracks and uses the three validation layers to each incoming position report.
    """

    def __init__(self, receiver_lat: float, receiver_lon: float,
                 receiver_alt_ft: float = 0.0):
        self.rx_lat = receiver_lat
        self.rx_lon = receiver_lon
        self.rx_alt = receiver_alt_ft
        self.tracks: dict[str, AircraftTrack] = {}
        self.stats = {
            "messages_processed": 0,
            "geometry_alerts": 0,
            "trajectory_alerts": 0,
            "timing_alerts": 0,
            "total_spoofed": 0,
        }
        self.lock = threading.Lock()

    def get_or_create_track(self, icao: str) -> AircraftTrack:
        if icao not in self.tracks:
            self.tracks[icao] = AircraftTrack(icao=icao)
        return self.tracks[icao]

    def purge_stale_tracks(self):
        """Remove tracks that have not been updated recently."""
        now = time.time()
        stale = [k for k, v in self.tracks.items()
                 if now - v.last_update > STALE_TRACK_TIMEOUT_S]
        for k in stale:
            del self.tracks[k]

    #Layer 1 - GPS-Based Geometry Sanity Check

    def check_geometry(self, track: AircraftTrack, report: PositionReport):
        """
        Verify that the reported position is plausible relative to the receiver's own location.
        """
        # 1a. Basic coordinate validity
        if not (-90 <= report.lat <= 90 and -180 <= report.lon <= 180):
            track.flag(f"Invalid coordinates ({report.lat:.4f}, {report.lon:.4f})", 100)
            self.stats["geometry_alerts"] += 1
            return

        # 1b. Altitude plausibility
        if report.altitude_ft < -1000 or report.altitude_ft > MAX_ALTITUDE_FT:
            track.flag(f"Implausible altitude: {report.altitude_ft:.0f} ft", 40)
            self.stats["geometry_alerts"] += 1

        # 1c. Range check
        dist_nm = geodesic_nm(self.rx_lat, self.rx_lon, report.lat, report.lon)
        if dist_nm > MAX_RANGE_NM:
            track.flag(f"Beyond max range: {dist_nm:.1f} NM (limit {MAX_RANGE_NM} NM)", 30)
            self.stats["geometry_alerts"] += 1

        # 1d. Line-of-sight check
        los_nm = max_line_of_sight_nm(report.altitude_ft, self.rx_alt)
        if dist_nm > los_nm * 1.2:  # 20 % margin for atmospheric refraction
            track.flag(f"Beyond line-of-sight: {dist_nm:.1f} NM (LoS limit ~{los_nm:.1f} NM at {report.altitude_ft:.0f} ft)", 25)
            self.stats["geometry_alerts"] += 1

        # 1e. Reported ground speed sanity check
        if report.ground_speed_kt > MAX_SPEED_KT:
            track.flag(f"Implausible speed: {report.ground_speed_kt:.0f} kt", 30)
            self.stats["geometry_alerts"] += 1

    #Layer 2 - Trajectory Continuity Validation

    def check_trajectory(self, track: AircraftTrack, report: PositionReport):
        """
        Ensure successive position reports follow a physically possible trajectory (reasonable speed, acceleration, turn rate, climb rate).
        """
        prev = track.prev
        if prev is None:
            return  # need at least two reports

        dt = report.timestamp - prev.timestamp
        if dt <= 0:
            return  # same-time messages handled by timing check

        # 2a. Positional jump
        dist_nm = geodesic_nm(prev.lat, prev.lon, report.lat, report.lon)
        implied_speed_kt = (dist_nm / dt) * 3600  # NM/s → kt

        # Only flags if implied speed is dramatically beyond max plausible.
        # Uses a higher multiplier (3x) to avoid false positives from SBS timing jitter and position update batching.
        # Scale penalty by severity, a 100 NM teleport scores much higher than a small overshoot.
        if implied_speed_kt > MAX_SPEED_KT * 3:
            severity = min(implied_speed_kt / (MAX_SPEED_KT * 3), 10)
            score = 35 * severity
            track.flag(f"Position jump implies {implied_speed_kt:.0f} kt (moved {dist_nm:.2f} NM in {dt:.2f}s)", score)
            self.stats["trajectory_alerts"] += 1

        # 2b. Acceleration check (only when speed is actually reported)
        if prev.ground_speed_kt > 0 and report.ground_speed_kt > 0:
            accel = abs(report.ground_speed_kt - prev.ground_speed_kt) / dt
            if accel > MAX_ACCEL_KT_PER_S:
                track.flag(f"Excessive acceleration: {accel:.1f} kt/s", 20)
                self.stats["trajectory_alerts"] += 1

        # 2c. Altitude rate check
        alt_change = abs(report.altitude_ft - prev.altitude_ft)
        alt_rate_fpm = (alt_change / dt) * 60
        if alt_rate_fpm > MAX_ALT_RATE_FPM:
            track.flag(f"Excessive climb/descent: {alt_rate_fpm:.0f} fpm", 25)
            self.stats["trajectory_alerts"] += 1

        # 2d. Heading continuity
        if prev.heading >= 0 and report.heading >= 0:
            hdg_change = abs(heading_diff(prev.heading, report.heading))
            hdg_rate = hdg_change / dt  # degrees/second
            if hdg_rate > MAX_HEADING_RATE_DEG_S:
                track.flag(f"Abrupt heading change: {hdg_rate:.1f} °/s ({hdg_change:.1f}° in {dt:.2f}s)", 20)
                self.stats["trajectory_alerts"] += 1

        # 2e. Cross-check: reported speed vs implied speed consistency
        # Skip when ground speed is 0 (unreported) — SBS MSG type 3 only contains position, speed comes separately in MSG type 4
        if report.ground_speed_kt > 50 and prev.ground_speed_kt > 50:
            speed_ratio = implied_speed_kt / report.ground_speed_kt
            if speed_ratio > 2.5 or speed_ratio < 0.2:
                track.flag(f"Speed inconsistency: reported {report.ground_speed_kt:.0f} kt but implied {implied_speed_kt:.0f} kt", 25)
                self.stats["trajectory_alerts"] += 1

    #Layer 3: Time-of-Arrival Validation

    def check_timing(self, track: AircraftTrack, report: PositionReport):
        """
        Check arrival times to detect delayed replays, duplicate transmissions, or timing anomalies.
        """
        prev = track.prev
        if prev is None:
            return

        dt = report.timestamp - prev.timestamp

        # 3a. Duplicate detection for nearly identical time & position
        if dt < MIN_INTER_ARRIVAL_S:
            pos_dist = geodesic_nm(prev.lat, prev.lon, report.lat, report.lon)
            if pos_dist < DUPLICATE_POSITION_THRESHOLD_NM:
                track.duplicate_count += 1
                track.flag(f"Duplicate message detected (Δt={dt*1000:.1f} ms, Δpos={pos_dist*NM_TO_KM*1000:.0f} m, dup #{track.duplicate_count})", 15)
                self.stats["timing_alerts"] += 1
                return

        # 3b. Burst detection for too many messages in short window
        if len(track.reports) >= 5:
            recent = track.reports[-5:]
            window = recent[-1].timestamp - recent[0].timestamp
            if window > 0:
                rate = len(recent) / window  # messages/second
                if rate > 10:  # ADS-B nominal rate is ~2/s
                    track.flag(f"Message burst: {rate:.1f} msg/s (expected ~2/s)", 20)
                    self.stats["timing_alerts"] += 1

        # 3c. Staleness / replay gap detection
        if dt > MAX_REPLAY_STALENESS_S:
            # Long gap followed by a position that doesn't make sense given the elapsed time could indicate a replay
            dist_nm = geodesic_nm(prev.lat, prev.lon, report.lat, report.lon)
            expected_max_dist = (MAX_SPEED_KT / 3600) * dt  #in NM
            if dist_nm < expected_max_dist * 0.01 and dt > 10:
                track.flag(f"Possible replay: {dt:.1f}s gap but position barely moved ({dist_nm:.3f} NM)", 30)
                self.stats["timing_alerts"] += 1

    #Main Processing

    def process_report(self, report: PositionReport) -> AircraftTrack:
        """
        Run all three detection layers on an incoming position report.
        Returns the updated aircraft track with anomaly scoring.
        """
        with self.lock:
            self.stats["messages_processed"] += 1
            track = self.get_or_create_track(report.icao)

            # Natural decay of anomaly score over time, legitimate aircraft recover from occasional jitter. Decay 2 points per second of silence.
            if track.last_update > 0:
                elapsed = report.timestamp - track.last_update
                decay = min(elapsed * 2, track.anomaly_score)
                track.anomaly_score = max(0, track.anomaly_score - decay)
                # Re-evaluate alert level after decay
                if track.anomaly_score < ALERT_THRESHOLD * 0.5:
                    track.alert_level = AlertLevel.CLEAN
                elif track.anomaly_score < ALERT_THRESHOLD:
                    track.alert_level = AlertLevel.SUSPICIOUS

            track.add_report(report)

            # Apply all three detection layers
            self.check_geometry(track, report)
            self.check_trajectory(track, report)
            self.check_timing(track, report)

            # Update global spoofed count
            if track.alert_level == AlertLevel.SPOOFED:
                self.stats["total_spoofed"] = sum(
                    1 for t in self.tracks.values()
                    if t.alert_level == AlertLevel.SPOOFED
                )

            return track

    def get_summary(self) -> dict:
        """Return current detection statistics."""
        with self.lock:
            active = {k: v for k, v in self.tracks.items()
                      if time.time() - v.last_update < STALE_TRACK_TIMEOUT_S}
            return {
                "active_tracks": len(active),
                "messages_processed": self.stats["messages_processed"],
                "alerts": {
                    "geometry": self.stats["geometry_alerts"],
                    "trajectory": self.stats["trajectory_alerts"],
                    "timing": self.stats["timing_alerts"],
                },
                "tracks_by_status": {
                    "clean": sum(1 for t in active.values()
                                 if t.alert_level == AlertLevel.CLEAN),
                    "suspicious": sum(1 for t in active.values()
                                      if t.alert_level == AlertLevel.SUSPICIOUS),
                    "spoofed": sum(1 for t in active.values()
                                   if t.alert_level == AlertLevel.SPOOFED),
                },
            }

#  NETWORK INPUT — CONNECT TO dump1090

def stream_from_dump1090(host: str, port: int, detector: SpoofDetector,
                         logger: logging.Logger):
    """
    Connect to dump1090's SBS output and feed messages into the detector.
    Automatically reconnects on connection loss.
    """
    while True:
        try:
            logger.info(f"Connecting to dump1090 at {host}:{port} ...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.settimeout(None)
            logger.info("Connected. Listening for ADS-B messages...")

            buf = ""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                buf += data.decode("ascii", errors="ignore")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    report = parse_sbs_line(line)
                    if report:
                        track = detector.process_report(report)
                        log_track_status(track, report, logger)

        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            logger.warning(f"Connection error: {e}. Retrying in 3s...")
            time.sleep(3)
        except KeyboardInterrupt:
            logger.info("Shutting down.")
            break


def log_track_status(track: AircraftTrack, report: PositionReport,
                     logger: logging.Logger):
    """Log messages for suspicious or spoofed tracks."""
    if track.alert_level == AlertLevel.CLEAN:
        return

    level = (logging.CRITICAL if track.alert_level == AlertLevel.SPOOFED
             else logging.WARNING)

    latest_anomaly = track.anomaly_log[-1] if track.anomaly_log else ""
    logger.log(
        level,
        f"{'SPOOFED' if track.alert_level == AlertLevel.SPOOFED else 'SUSPICIOUS'} | ICAO={track.icao} callsign={report.callsign or 'N/A':8s} | pos=({report.lat:.4f},{report.lon:.4f}) alt={report.altitude_ft:.0f}ft spd={report.ground_speed_kt:.0f}kt | score={track.anomaly_score:.0f} | {latest_anomaly}"
    )

# File input for testing with recorded data

def process_file(filepath: str, detector: SpoofDetector,
                 logger: logging.Logger):
    """Process a recorded SBS file (one message per line)."""
    logger.info(f"Processing file: {filepath}")
    count = 0
    with open(filepath, "r") as f:
        for line in f:
            report = parse_sbs_line(line)
            if report:
                track = detector.process_report(report)
                log_track_status(track, report, logger)
                count += 1
    logger.info(f"Processed {count} position messages from file.")


# Status Display

def status_printer(detector: SpoofDetector, interval: int = 15):
    """Background thread that periodically prints detection statistics."""
    while True:
        time.sleep(interval)
        detector.purge_stale_tracks()
        summary = detector.get_summary()
        print(f"\n{'─' * 60}")
        print(f"  Status @ {datetime.now().strftime('%H:%M:%S')}  |  msgs={summary['messages_processed']}  tracks={summary['active_tracks']}  clean={summary['tracks_by_status']['clean']}  suspicious={summary['tracks_by_status']['suspicious']}  SPOOFED={summary['tracks_by_status']['spoofed']}")
        print(f"  Alerts → geometry={summary['alerts']['geometry']}  trajectory={summary['alerts']['trajectory']}  timing={summary['alerts']['timing']}")
        print(f"{'─' * 60}\n")

def main():
    parser = argparse.ArgumentParser(
        description="ADS-B Spoofing & Replay Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live detection (auto-detect location via IP):
  python3 adsb_spoof_detector.py

  # Live detection with explicit coordinates:
  python3 adsb_spoof_detector.py --lat 43.0846 --lon -77.6743

  # Process a recorded SBS file:
  python3 adsb_spoof_detector.py --file data.sbs
        """,
    )
    parser.add_argument("--lat", type=float, default=None,
                        help="Receiver latitude (auto-detected if omitted)")
    parser.add_argument("--lon", type=float, default=None,
                        help="Receiver longitude (auto-detected if omitted)")
    parser.add_argument("--alt", type=float, default=0.0,
                        help="Receiver altitude (feet MSL, default=0)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="dump1090 host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=30003,
                        help="dump1090 SBS port (default: 30003)")
    parser.add_argument("--file", type=str, default=None,
                        help="Process recorded SBS file instead of live")
    parser.add_argument("--json", action="store_true",
                        help="Output final summary as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose (DEBUG) logging")

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("adsb_detector")

    # Resolve receiver location
    if args.lat is not None and args.lon is not None:
        rx_lat, rx_lon = args.lat, args.lon
        loc_source = "manual"
    else:
        logger.info("No --lat/--lon provided, auto-detecting location via IP...")
        result = get_location()
        if result is None:
            logger.error("Could not auto-detect location. Please provide --lat and --lon manually.")
            sys.exit(1)
        rx_lat, rx_lon, loc_desc = result
        loc_source = f"auto-detected ({loc_desc})"

    # Banner
    logger.info("╔══════════════════════════════════════════════════════════╗")
    logger.info("║       ADS-B Spoofing & Replay Detection System           ║")
    logger.info("╚══════════════════════════════════════════════════════════╝")
    logger.info(f"  Receiver: ({rx_lat:.4f}, {rx_lon:.4f}) [{loc_source}]")

    # Initialize detector
    detector = SpoofDetector(
        receiver_lat=rx_lat,
        receiver_lon=rx_lon,
        receiver_alt_ft=args.alt,
    )

    if args.file:
        process_file(args.file, detector, logger)
        if args.json:
            print(json.dumps(detector.get_summary(), indent=2))

        # Print per-track results
        logger.info("\n── Per-Track Results ──")
        for icao, track in sorted(detector.tracks.items()):
            status = track.alert_level.name
            logger.info(f"  {icao} ({track.reports[-1].callsign or 'N/A':8s}) | {status:10s} | score={track.anomaly_score:.0f} | msgs={len(track.reports)}")
            if track.anomaly_log:
                for entry in track.anomaly_log[-3:]:  # last 3 anomalies
                    logger.info(f"      {entry}")

    else:
        # Live mode — connect to dump1090
        # Start status printer in background
        status_thread = threading.Thread(
            target=status_printer, args=(detector, 15), daemon=True
        )
        status_thread.start()

        stream_from_dump1090(args.host, args.port, detector, logger)

        if args.json:
            print(json.dumps(detector.get_summary(), indent=2))


if __name__ == "__main__":
    main()