import base64
import time

import requests


VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses"


def create_url_id(url: str) -> str:
    """
    Convert a URL into VirusTotal's unpadded URL-safe
    Base64 identifier.
    """
    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("utf-8")

    return encoded.rstrip("=")


def build_result(stats: dict, source: str) -> dict:
    """
    Convert VirusTotal statistics into the format
    expected by the Streamlit application.
    """
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout_count = int(stats.get("timeout", 0))

    total_engines = (
        malicious
        + suspicious
        + harmless
        + undetected
        + timeout_count
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
        "timeout": timeout_count,
        "total_engines": total_engines,
        "source": source
    }


def handle_common_errors(response: requests.Response) -> dict | None:
    """
    Return a user-friendly error for common API responses.
    Return None when no common error occurred.
    """
    if response.status_code == 401:
        return {
            "status": "error",
            "message": (
                "VirusTotal API key is invalid, unauthorized, "
                "or the VirusTotal account is not active."
            )
        }

    if response.status_code == 403:
        return {
            "status": "error",
            "message": (
                "VirusTotal denied this request. Your API key "
                "may not have permission for this operation."
            )
        }

    if response.status_code == 429:
        return {
            "status": "error",
            "message": (
                "VirusTotal API limit has been reached. "
                "Please wait before scanning another URL."
            )
        }

    if response.status_code in {503, 504}:
        return {
            "status": "error",
            "message": (
                "VirusTotal is temporarily unavailable. "
                "Please try again later."
            )
        }

    return None


def get_existing_url_report(
    url: str,
    headers: dict
) -> dict | None:
    """
    Retrieve an existing VirusTotal URL report.

    Returns:
        A result dictionary when a report or API error exists.
        None when the URL is not present and should be submitted.
    """
    url_id = create_url_id(url)

    try:
        response = requests.get(
            f"{VT_URL_ENDPOINT}/{url_id}",
            headers=headers,
            timeout=20
        )

    except requests.Timeout:
        return {
            "status": "error",
            "message": (
                "VirusTotal report request timed out."
            )
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": (
                "Could not connect to VirusTotal."
            )
        }

    common_error = handle_common_errors(response)

    if common_error:
        return common_error

    if response.status_code == 404:
        return None

    if response.status_code != 200:
        return {
            "status": "error",
            "message": (
                "VirusTotal report lookup failed with "
                f"error code {response.status_code}."
            )
        }

    try:
        data = response.json()
    except ValueError:
        return {
            "status": "error",
            "message": (
                "VirusTotal returned an invalid response."
            )
        }

    attributes = (
        data.get("data", {})
        .get("attributes", {})
    )

    stats = attributes.get(
        "last_analysis_stats",
        {}
    )

    if not stats:
        return None

    result = build_result(
        stats=stats,
        source="existing_report"
    )

    result["last_analysis_date"] = attributes.get(
        "last_analysis_date"
    )

    return result


def submit_url_for_scan(
    url: str,
    headers: dict
) -> dict:
    """
    Submit a URL to VirusTotal and return its analysis ID.
    """
    try:
        response = requests.post(
            VT_URL_ENDPOINT,
            headers=headers,
            data={"url": url},
            timeout=20
        )

    except requests.Timeout:
        return {
            "status": "error",
            "message": (
                "VirusTotal URL submission timed out."
            )
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": (
                "Could not submit the URL to VirusTotal."
            )
        }

    common_error = handle_common_errors(response)

    if common_error:
        return common_error

    if response.status_code not in {200, 201}:
        return {
            "status": "error",
            "message": (
                "VirusTotal could not accept the URL. "
                f"Error code: {response.status_code}."
            )
        }

    try:
        data = response.json()
    except ValueError:
        return {
            "status": "error",
            "message": (
                "VirusTotal returned an invalid submission response."
            )
        }

    analysis_id = (
        data.get("data", {})
        .get("id")
    )

    if not analysis_id:
        return {
            "status": "error",
            "message": (
                "VirusTotal did not return an analysis ID."
            )
        }

    return {
        "status": "submitted",
        "analysis_id": analysis_id
    }


def wait_for_analysis(
    analysis_id: str,
    headers: dict,
    max_attempts: int = 3,
    wait_seconds: int = 16
) -> dict:
    """
    Poll VirusTotal until the submitted analysis completes.

    The delay is intentionally long because the free public API
    permits only a small number of requests per minute.
    """
    analysis_url = (
        f"{VT_ANALYSIS_ENDPOINT}/{analysis_id}"
    )

    for attempt in range(max_attempts):

        if attempt > 0:
            time.sleep(wait_seconds)

        try:
            response = requests.get(
                analysis_url,
                headers=headers,
                timeout=20
            )

        except requests.Timeout:
            return {
                "status": "error",
                "message": (
                    "VirusTotal analysis request timed out."
                )
            }

        except requests.RequestException:
            return {
                "status": "error",
                "message": (
                    "Could not retrieve the VirusTotal analysis."
                )
            }

        common_error = handle_common_errors(response)

        if common_error:
            return common_error

        if response.status_code != 200:
            return {
                "status": "error",
                "message": (
                    "VirusTotal analysis lookup failed with "
                    f"error code {response.status_code}."
                )
            }

        try:
            data = response.json()
        except ValueError:
            return {
                "status": "error",
                "message": (
                    "VirusTotal returned an invalid analysis response."
                )
            }

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        analysis_status = attributes.get(
            "status",
            "unknown"
        )

        if analysis_status == "completed":
            stats = attributes.get(
                "stats",
                {}
            )

            if not stats:
                return {
                    "status": "error",
                    "message": (
                        "The scan completed, but no engine "
                        "statistics were returned."
                    )
                }

            result = build_result(
                stats=stats,
                source="fresh_scan"
            )

            result["analysis_status"] = "completed"

            return result

    return {
        "status": "pending",
        "message": (
            "The URL was submitted successfully, but the "
            "VirusTotal scan is still processing. Please wait "
            "about one minute and analyze the same URL again."
        )
    }


def check_virustotal_url(
    url: str,
    api_key: str
) -> dict:
    """
    Retrieve an existing URL report or submit the URL for
    a fresh VirusTotal scan when no report exists.
    """
    cleaned_url = url.strip()

    if not cleaned_url:
        return {
            "status": "error",
            "message": "No URL was provided."
        }

    if not api_key:
        return {
            "status": "error",
            "message": (
                "VirusTotal API key is missing."
            )
        }

    headers = {
        "x-apikey": api_key.strip()
    }

    existing_report = get_existing_url_report(
        cleaned_url,
        headers
    )

    if existing_report is not None:
        return existing_report

    submission = submit_url_for_scan(
        cleaned_url,
        headers
    )

    if submission.get("status") != "submitted":
        return submission

    return wait_for_analysis(
        analysis_id=submission["analysis_id"],
        headers=headers
    )
