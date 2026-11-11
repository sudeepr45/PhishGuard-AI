"""Bounded, offline parsing for email URL triage. No message data is persisted."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

MAX_EMAIL_BYTES = 256 * 1024
MAX_MIME_PARTS = 30
MAX_EXTRACTED_URLS = 25
MAX_PART_BYTES = 64 * 1024
_URL_RE = re.compile(r"(?i)\b(?:https?://|ftp://|sftp://|file://|javascript:|data:|mailto:)[^\s<>\"']+")
_DEFANGED_RE = re.compile(r"(?i)\b(?:hxxps?://|https?\[://\]|[a-z0-9-]+\[\.\][a-z0-9.-]+)")


class EmailInputError(ValueError):
    pass


@dataclass
class ExtractedLink:
    url: str
    sources: set[str] = field(default_factory=set)


@dataclass
class EmailTriageInput:
    headers: dict[str, str | None]
    authentication_results: list[str]
    received_count: int
    links: list[ExtractedLink]
    unsupported_links: list[dict[str, str]]
    truncated: bool
    mime_parts_examined: int


class _HrefParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, value in attrs:
                if name.lower() == "href" and value:
                    self.hrefs.append(value)

    handle_startendtag = handle_starttag


def _clean_url_candidate(candidate: str) -> str:
    return candidate.rstrip(".,;:!?)]}>")


def parse_email(raw_email: str) -> EmailTriageInput:
    if not isinstance(raw_email, str) or not raw_email.strip():
        raise EmailInputError("Paste email content to analyze.")
    try:
        raw = raw_email.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise EmailInputError("Email content contains invalid text encoding.") from None
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailInputError("Email exceeds the 256 KiB size limit.")

    message = BytesParser(policy=policy.default).parsebytes(raw)
    headers = {name: str(message.get(name))[:4096] if message.get(name) is not None else None
               for name in ("From", "Reply-To", "Return-Path", "Subject", "Date")}
    auth_results = [str(value)[:4096] for value in message.get_all("Authentication-Results", [])[:10]]
    links: dict[str, ExtractedLink] = {}
    unsupported: list[dict[str, str]] = []
    unsupported_seen: set[tuple[str, str]] = set()
    parts_examined = 0
    truncated = False

    def record(candidate: str, source: str):
        nonlocal truncated
        candidate = candidate.strip().strip("<>")
        if not candidate:
            return
        def unsupported_link(reason: str):
            nonlocal truncated
            identity = (candidate, reason)
            if identity in unsupported_seen:
                return
            if len(links) + len(unsupported) >= MAX_EXTRACTED_URLS:
                truncated = True
                return
            unsupported_seen.add(identity)
            unsupported.append({"value": candidate[:2048], "reason": reason})

        if _DEFANGED_RE.search(candidate):
            unsupported_link("defanged; not treated as an active URL")
            return
        if re.match(r"(?i)^(?:javascript|data|mailto|ftp):", candidate):
            unsupported_link("unsupported URL scheme")
            return
        if not re.match(r"(?i)^https?://", candidate):
            return
        if len(candidate) > 8192:
            unsupported_link("URL exceeds the supported length limit")
            return
        # The API's URLRequest performs the canonical HTTP(S) validation. Keep the
        # original candidate here; normalization happens only at inference time.
        if candidate not in links:
            if len(links) >= MAX_EXTRACTED_URLS:
                truncated = True
                return
            links[candidate] = ExtractedLink(candidate)
        links[candidate].sources.add(source)

    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        parts_examined += 1
        if parts_examined > MAX_MIME_PARTS:
            truncated = True
            break
        content_type = part.get_content_type().lower()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                raw_payload = part.get_payload()
                if isinstance(raw_payload, str):
                    payload = raw_payload.encode(part.get_content_charset() or "utf-8", errors="replace")
                else:
                    continue
            if len(payload) > MAX_PART_BYTES:
                payload = payload[:MAX_PART_BYTES]
                truncated = True
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except (LookupError, UnicodeError, ValueError):
            continue
        if content_type == "text/plain":
            for match in _URL_RE.finditer(text):
                record(_clean_url_candidate(match.group(0)), "plain_text")
        else:
            parser = _HrefParser()
            try:
                parser.feed(text)
                parser.close()
            except Exception:
                # HTMLParser is deliberately used only to inspect literal hrefs.
                pass
            for href in parser.hrefs[:MAX_EXTRACTED_URLS * 2]:
                record(href, "html_href")

    return EmailTriageInput(
        headers=headers,
        authentication_results=auth_results,
        received_count=len(message.get_all("Received", [])),
        links=list(links.values()),
        unsupported_links=unsupported,
        truncated=truncated,
        mime_parts_examined=min(parts_examined, MAX_MIME_PARTS),
    )
