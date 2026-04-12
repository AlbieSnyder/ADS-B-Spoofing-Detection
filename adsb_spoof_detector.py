from geopy.distance import geodesic
import math
import threading
import time


#CONSTANTS
EARTH_RADIUS_NM = 3440.065 #nautical miles
EARTH_RADIUS_KM = 6371.0
NM_TO_KM = 1.854
FT_TO_M = 0.3048
KT_TO_KMH = 1.852 #Knots to Kilometers / Hour

# Detection thresholds (Can be changed)
MAX_RANGE_NM = 250 # max plausible reception range (NM)
MAX_ALTITUDE_FT = 60000 # max plausible altitude (feet)
MAX_SPEED_KT = 700 # max plausible speed for commercial aircraft (knots)
MAX_ACCEL_KT_PER_S = 15 # max plausible acceleration (knots/second)
MAX_ALT_RATE_FPM = 8000 # max altitude rate of change (feet/minute)
MAX_HEADING_RATE_DEG_S = 6.0 # max heading change rate (degrees/second)

# Time-of-arrival thresholds
EXPECTED_UPDATE_INTERVAL_S = 0.5 # ADS-B update interval
MIN_INTER_ARRIVAL_S = 0.05 # below this indicates a likely duplicate message
DUPLICATE_POSITION_THRESHOLD_NM = 0.01 # positions closer than this are "same"
MAX_REPLAY_STALENESS_S = 5.0 # message older than this is suspect
STALE_TRACK_TIMEOUT_S = 60.0 # drop track after this silence

#Scoring
ALERT_THRESHOLD = 50

#Structures
class AlertLevel(Enum):
    CLEAN = auto()
    SUSPICIOUS = auto()
    SPOOFED = auto()

@dataclass
class PositionReport:
    """singular ADS-B position message"""
    icao: str #6-Hex ICAO address
    callsign: str #flight callsign (can be empty)
    lat: float # degrees
    lon: float # degrees
    altitude_ft: float #ft
    ground_speed_kt: float #knots
    heading: float
    vertical_rate_fpm: float #ft per minute
    timestamp: float
    raw_line: str = "" #original SBS line

@dataclass
class AircraftTrack:
    icao: str
    reports: List[PositionReport] = field(default_factory=list)
    anomaly_score: float = 0.0
    alert_level: AlertLevel = AlertLevel.CLEAN
    anomaly_log: list[str] = field(default_facotry=list)
    duplicate_count: int = 0
    last_update: float = 0.0

    def add_report(self, report: PositionReport):
        self.reports.append(report)
        self.last_update = report.timestamp
        # Keeps a sliding window of the last 50 reports
        if len(self.reports) > 50:
            self.reports = self.reports[-50:]


    @property
    def prev(self) -> Optional[PositionReport]:
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


#Geometry Utilities

def geodesic_nm(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """geodesic distance in NM"""
    return geodesic((lat1, lon1), (lat2, lon2)).nautical

def heading_diff(h1: float, h2: float) -> float:
    """Smallest (signed) angular difference between two headings"""
    d = (h2 - h1 + 180) % 360 - 180
    return d

def max_line_of_sight_nm(alt_ft: float, receiver_alt_ft: float = 0) -> float:
    """Approximate line-of-sight range using the 4/3 earth model described here https://www.researchgate.net/figure/Radar-horizon-vs-altitude-for-4-3-earth-model_fig2_277011644"""
    alt_m = alt_ft * FT_TO_M
    rx_m = receiver_alt_ft * FT_TO_M
    return 1.23 * (math.sqrt(max(alt_ft, 0)) + math.sqrt(max(receiver_alt_ft, 0)))

#Detection Checks

class SpoofDetector:

    def __init__(self, receiver_lat: float, receiver_lon: float, receiver_alt_ft: float = 0.0):
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
        """Remove tracks old tracks"""
        now = time.time()
        stale = [k for k, v in self.tracks.items()
                 if now - v.last_update > STALE_TRACK_TIMEOUT_S]
        for k in stale:
            del self.tracks[k]

    # GPS-Based Geometry Checks

    def check_geometry(self, track: AircraftTrack, report: PositionReport):
        """Check if reported position is plausible relative to the receiver's location"""
        #Basic coordinate check
        if not (-90 <= report.lat <= 90 and -180 <= report.lon <= 180):
            track.flag(f"Invalid coordinates ({report.lat:.4f}, {report.lon:.4f})", 100)
            self.stats["geometry_alerts"] += 1
            return
        
        #Altitude check
        if report.altitude_ft < -1000 or report.altitude_ft > MAX_ALTITUDE_FT:
            track.flag(f"Implausible altitude: {report.altitude_ft:.0f} ft", 40)
            self.stats["geometry_alerts"] += 1

        #Range check
        dist_nm = geodesic_nm(self.rx_lat, self.rx_lon, report.lat, report.lon)
        if dist_nm > MAX_RANGE_NM:
            track.flag(f"Beyond max range: {dist_nm:.1f} NM (limit {MAX_RANGE_NM} NM)", 30)
            self.stats["geometry_alerts"] += 1

        #LoS Check
        los_nm = max_line_of_sight_nm(report.altitude_ft, self.rx_alt)
        if dist_nm > los_nm * 1.2:  # 20 % margin because this isn't an exact thing I think
            track.flag(f"Beyond line-of-sight: {dist_nm:.1f} NM (LoS limit ~{los_nm:.1f} NM at {report.altitude_ft:.0f} ft)", 25)
            self.stats["geometry_alerts"] += 1

        #Groundspeed Check
        if report.ground_speed_kt > MAX_SPEED_KT:
            track.flag(f"Implausible speed: {report.ground_speed_kt:.0f} kt", 30)
            self.stats["geometry_alerts"] += 1

    #Trajectory Checks

    def check_trajectory(self, track: AircraftTrack, report: PositionReport):
        """Check if successsive position reports follow a realistic trajectory"""

        prev = track.prev
        if prev is None:
            return
        
        dt = report.timestamp - prev.timestamp
        if dt <= 0:
            return # same-time messages handled elsewhere by timing check
        
        #position jump check
        dist_nm = geodesic_nm(prev.lat, prev.lon, report.lat, report.lon)
        implied_speed_kt = (dist_nm / dt) * 3600 #NM/s to knots

        if implied_speed_kt > MAX_SPEED_KT * 1.5:
            track.flag(f"Position jump implies {implied_speed_kt:.0f} kt (moved {dist_nm:.2f} NM in {dt:.2f}s)", 35)
            self.stats["trajectory_alerts"] += 1

        #Acceleration check
        if prev.ground_speed_kt > 0 and report.ground_speed_kt > 0:
            accel = abs(report.ground_speed_kt - prev.ground_speed_kt)
            if accel > MAX_ACCEL_KT_PER_S:
                track.flag(f"Impossible acceleration: {accel:.1f} kt/s", 20)
                self.stats["trajectory_alerts"] += 1

        #Altitute Rate Check
        alt_change = abs(report.altitude_ft - prev.altitude_ft)
        alt_rate_fpm = (alt_change / dt) * 60
        if alt_rate_fpm > MAX_ALT_RATE_FPM:
            track.flag(f"Excessive climb/descent: {alt_rate_fpm:.0f} fpm", 25)
            self.stats["trajectory_alerts"] += 1

        #Heading check (basically the plane can't do a 180)
        if prev.heading >= 0 and report.heading >= 0:
            hdg_change = abs(heading_diff(prev.heading, report.heading))
            hdg_rate = hdg_change / dt  # degrees/second
            if hdg_rate > MAX_HEADING_RATE_DEG_S:
                track.flag(f"Abrupt heading change: {hdg_rate:.1f} °/s ({hdg_change:.1f}° in {dt:.2f}s)", 20)
                self.stats["trajectory_alerts"] += 1

        #Cross-Check (reported speed vs calculated speed)
        if report.ground_speed_kt > 50:  # only meaningful at flying speeds
            speed_ratio = implied_speed_kt / report.ground_speed_kt
            if speed_ratio > 2.5 or speed_ratio < 0.2:
                track.flag(f"Speed inconsistency: reported {report.ground_speed_kt:.0f} kt but implied {implied_speed_kt:.0f} kt", 25)
                self.stats["trajectory_alerts"] += 1