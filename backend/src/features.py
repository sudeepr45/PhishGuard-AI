"""Deterministic lexical features derived only from URL text."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "hostname_dot_count",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "is_ip_hostname",
    "uses_https",
    "authority_has_at_sign",
    "percent_encoding_count",
    "malformed_percent_count",
    "path_length",
    "path_segment_count",
    "path_has_dot_segment",
    "query_length",
    "query_parameter_count",
    "has_fragment",
)

_VALID_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_SUFFIX_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def extract_url_features(url: str) -> dict[str, int]:
    """Return fixed-order integer features; never resolves or fetches the URL.

    Malformed input is still measurable. Callers that require a valid URL must
    validate it separately. All measurements describe the supplied string,
    not the remote host or page.
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        path = parsed.path
        query = parsed.query
        authority = parsed.netloc
        scheme = parsed.scheme.lower()
    except (ValueError, UnicodeError):
        hostname, path, query, authority, scheme = "", "", "", "", ""

    host_for_measurement = hostname.rstrip(".")
    try:
        ascii_host = host_for_measurement.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host_for_measurement
    labels = [label for label in ascii_host.split(".") if label]
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    segments = [segment for segment in path.split("/") if segment]
    query_parameters = [part for part in query.split("&") if part]
    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "hostname_dot_count": hostname.count("."),
        "subdomain_count": (
            len([part for part in _SUFFIX_EXTRACTOR(ascii_host).subdomain.split(".") if part])
            if labels and not is_ip else 0
        ),
        "hyphen_count": url.count("-"),
        "digit_count": sum(char.isdigit() for char in url),
        "is_ip_hostname": is_ip,
        "uses_https": int(scheme == "https"),
        "authority_has_at_sign": int("@" in authority),
        "percent_encoding_count": len(_VALID_PERCENT.findall(url)),
        "malformed_percent_count": len(_BAD_PERCENT.findall(url)),
        "path_length": len(path),
        "path_segment_count": len(segments),
        "path_has_dot_segment": int(any(part in {".", ".."} for part in segments)),
        "query_length": len(query),
        "query_parameter_count": len(query_parameters),
        "has_fragment": int(bool(parsed.fragment)) if "parsed" in locals() else 0,
    }
