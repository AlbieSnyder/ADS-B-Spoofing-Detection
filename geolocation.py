import json
import urllib.request

def get_location() -> tuple[float, float, str] | None:
    """
    Detect the current location from the machine's public IP address using the ipinfo.io API
    Returns:
        (latitude, longitude, description) on success, or None on failure.
    """
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": "adsb-detector/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
 
        loc = data.get("loc", "")
        if not loc or "," not in loc:
            return None
 
        lat, lon = loc.split(",")
        city = data.get("city", "")
        region = data.get("region", "")
        country = data.get("country", "")
        description = ", ".join(part for part in [city, region, country] if part)
 
        return float(lat), float(lon), description
 
    except Exception:
        return None