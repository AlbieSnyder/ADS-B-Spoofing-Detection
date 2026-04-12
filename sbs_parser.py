import time
from dataclasses import dataclass

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

def parse_sbs_line(line: str) -> PositionReport | None:
    """Parse a SBS Basestation message line from dump1090"""
    """Returns PositionReport on success and None if not usable"""

    try:
        parts = line.strip().split(",")
        if len(parts) < 22 or parts[0] != "MSG":
            return None
 
        msg_type = parts[1].strip()
        # We primarily want MSG types 2, 3 which contain position
        if msg_type not in ("2", "3"):
            return None
 
        icao = parts[4].strip().upper()
        if not icao or len(icao) != 6:
            return None
 
        # Extract fields (empty strings become 0 / defaults)
        callsign = parts[10].strip()
        lat_s = parts[14].strip()
        lon_s = parts[15].strip()
 
        if not lat_s or not lon_s:
            return None
 
        lat = float(lat_s)
        lon = float(lon_s)
 
        alt_s = parts[11].strip()
        altitude = float(alt_s) if alt_s else 0.0
 
        gs_s = parts[12].strip()
        ground_speed = float(gs_s) if gs_s else 0.0
 
        trk_s = parts[13].strip()
        heading = float(trk_s) if trk_s else -1.0
 
        vr_s = parts[16].strip()
        vertical_rate = float(vr_s) if vr_s else 0.0
 
        return PositionReport(
            icao=icao,
            callsign=callsign,
            lat=lat,
            lon=lon,
            altitude_ft=altitude,
            ground_speed_kt=ground_speed,
            heading=heading,
            vertical_rate_fpm=vertical_rate,
            timestamp=time.time(),
            raw_line=line.strip(),
        )
 
    except (ValueError, IndexError):
        return None