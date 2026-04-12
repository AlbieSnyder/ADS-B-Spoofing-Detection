from geopy.distance import geodesic
import math


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
    ground_speek_kt: float #knots
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