import sqlite3

from fastapi.testclient import TestClient

from backend.src.api import create_app
from backend.src.email_analysis import MAX_EMAIL_BYTES, EmailInputError, parse_email


def test_parses_headers_plain_html_and_deduplicates_urls():
    parsed = parse_email("""From: Sender <sender@example.test>
Reply-To: reply@example.test
Subject: Hello
Authentication-Results: mx; dkim=pass
Received: by local
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=x

--x
Content-Type: text/plain; charset=utf-8

Visit https://example.test/path and https://other.example/path.
--x
Content-Type: text/html; charset=utf-8

<a href="https://example.test/path">same</a><a href="https://html.example">html</a>
--x--
""")
    assert parsed.headers["From"] == "Sender <sender@example.test>"
    assert parsed.headers["Reply-To"] == "reply@example.test"
    assert parsed.authentication_results == ["mx; dkim=pass"]
    assert parsed.received_count == 1
    assert len(parsed.links) == 3
    assert parsed.links[0].sources == {"plain_text", "html_href"}


def test_defanged_and_non_http_links_are_never_active():
    parsed = parse_email("""Content-Type: text/html

<a href="hxxps://phish[.]example">d</a><a href="javascript:alert(1)">x</a>
""")
    assert parsed.links == []
    assert len(parsed.unsupported_links) == 2
    plain = parse_email("Content-Type: text/plain\n\nftp://files.example/test")
    assert plain.links == []
    assert plain.unsupported_links[0]["reason"] == "unsupported URL scheme"


def test_email_size_limit_is_enforced():
    try:
        parse_email("x" * (MAX_EMAIL_BYTES + 1))
        assert False, "expected oversize input rejection"
    except EmailInputError as error:
        assert "256 KiB" in str(error)


def test_encoded_subject_and_malformed_message_are_safely_parsed():
    parsed = parse_email("Subject: =?utf-8?b?SGVsbG8=?=\n\ntext https://example.test")
    assert parsed.headers["Subject"] == "Hello"
    assert len(parsed.links) == 1
    malformed = parse_email("Content-Type: multipart/mixed; boundary=missing\n\n--missing\nbody")
    assert malformed.headers["Subject"] is None


def test_part_and_url_caps_are_reported():
    message = ["MIME-Version: 1.0", "Content-Type: multipart/mixed; boundary=x", ""]
    for index in range(35):
        message.extend(["--x", "Content-Type: text/plain", "", f"https://host{index}.example/path"])
    message.extend(["--x--", ""])
    parsed = parse_email("\n".join(message))
    assert parsed.truncated is True
    assert parsed.mime_parts_examined == 30
    html = "Content-Type: text/html\n\n" + "".join(
        f'<a href="https://host{index}.example/path">x</a>' for index in range(40)
    )
    parsed_links = parse_email(html)
    assert len(parsed_links.links) == 25
    assert parsed_links.truncated is True


def test_email_route_returns_model_results_without_saving_message_or_urls(tmp_path):
    database = tmp_path / "email-history.sqlite3"
    client = TestClient(create_app(database_path=database))
    message = """From: sender@example.test
Reply-To: reply@example.test
Subject: Please review
Authentication-Results: forged.example; dmarc=pass
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary=boundary

--boundary
Content-Type: text/plain

Please visit https://example.com/login
--boundary
Content-Type: text/html

<a href="https://example.org/verify">Review account</a>
--boundary--
"""
    response = client.post("/analyze-email", json={"raw_email": message})
    assert response.status_code == 200
    body = response.json()
    assert body["headers"]["From"] == "sender@example.test"
    assert body["headers"]["Reply-To"] == "reply@example.test"
    assert body["extracted_link_count"] == 2
    assert len(body["links"]) == 2
    for link in body["links"]:
        assert link["model_version"] == "url-classifier-3"
        assert len(link["measured_features"]) == 17
        assert link["explanation"] is not None
        assert len(link["explanation"]["feature_contributions"]) == 17
        assert isinstance(link["novelty_detection"]["available"], bool)
    assert "not been independently verified" in body["authentication_results_warning"]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM analysis_history").fetchone()[0] == 0


def test_email_without_supported_links_is_explicitly_unassessed(tmp_path):
    client = TestClient(create_app(database_path=tmp_path / "empty.sqlite3"))
    response = client.post("/analyze-email", json={"raw_email": "Subject: No links\n\nHello"})
    assert response.status_code == 200
    body = response.json()
    assert body["extracted_link_count"] == 0
    assert "could not assess" in body["triage_summary"]


def test_email_oversize_request_is_rejected(tmp_path):
    client = TestClient(create_app(database_path=tmp_path / "oversize.sqlite3"))
    response = client.post("/analyze-email", json={"raw_email": "x" * (MAX_EMAIL_BYTES + 1)})
    assert response.status_code in {413, 422}
