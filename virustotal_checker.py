import base64
import requests


VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"


def create_url_id(url: str) -> str:
    """
    Convert a URL into the unpadded URL-safe Base64 identifier
    required by VirusTotal API v3.
    """
    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


def check_virustotal_url(url: str, api_key: str) -> dict:
    """
    Retrieve an existing VirusTotal reputation report for a URL.

    This function does not submit the URL for a new scan.
    """

    if not url.strip():
        return {
            "status": "error",
            "message": "No URL was provided."
        }

    if not api_key:
        return {
            "status": "error",
            "message": "VirusTotal API key is missing."
        }

    url_id = create_url_id(url.strip())

    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(
            f"{VT_URL_ENDPOINT}/{url_id}",
            headers=headers,
            timeout=15
        )

    except requests.Timeout:
        return {
            "status": "error",
            "message": "VirusTotal request timed out."
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": "Could not connect to VirusTotal."
        }

    if response.status_code == 404:
        return {
            "status": "not_found",
            "message": (
                "This URL does not currently have a report "
                "in the VirusTotal database."
            )
        }

    if response.status_code == 401:
        return {
            "status": "error",
            "message": "VirusTotal API key is invalid or unauthorized."
        }

    if response.status_code == 429:
        return {
            "status": "error",
            "message": (
                "VirusTotal API request limit has been reached. "
                "Please try again later."
            )
        }

    if response.status_code != 200:
        return {
            "status": "error",
            "message": (
                f"VirusTotal returned error code "
                f"{response.status_code}."
            )
        }

    data = response.json()

    attributes = (
        data.get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    total_engines = (
        malicious
        + suspicious
        + harmless
        + undetected
    )

    if malicious >= 3:
        reputation_level = "HIGH"

    elif malicious >= 1 or suspicious >= 2:
        reputation_level = "MEDIUM"

    else:
        reputation_level = "LOW"

    return {
        "status": "success",
        "reputation_level": reputation_level,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total_engines,
        "last_analysis_date": attributes.get(
            "last_analysis_date"
        )
    }
