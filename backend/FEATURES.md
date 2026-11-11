# URL feature definitions

All features are deterministic measurements of the submitted URL string. They do not establish that a site exists, is malicious, or is safe. No DNS query, HTTP request, page parsing, or script execution occurs. Hostname parsing uses Python's URL parser and the pinned `tldextract` package with network suffix-list updates disabled.

| Feature | Definition |
|---|---|
| `url_length` | Number of Python Unicode code points in the full input string. |
| `hostname_length` | Number of Unicode code points in the parsed hostname, excluding user-info and port. |
| `hostname_dot_count` | Literal `.` characters in the parsed hostname. |
| `subdomain_count` | Number of hostname labels in the Public Suffix List-aware subdomain portion; zero for IP literals or absent hosts. |
| `hyphen_count` | Literal hyphens across the full URL string. |
| `digit_count` | Unicode characters for which Python `str.isdigit()` is true across the full URL. |
| `is_ip_hostname` | One if Python `ipaddress` parses the hostname as an IP literal, otherwise zero. |
| `uses_https` | One when the parsed URL scheme is HTTPS, case-insensitively. This says nothing about the destination's live TLS configuration. |
| `authority_has_at_sign` | One when the parsed authority contains `@`; this is a visible syntax feature, not a verdict. |
| `percent_encoding_count` | Number of `%` characters that begin a complete two-hex-digit escape. |
| `malformed_percent_count` | Number of `%` characters not followed by two hex digits. |
| `path_length` | Number of code points in the parsed path. |
| `path_segment_count` | Number of nonempty slash-separated path segments. |
| `path_has_dot_segment` | One when a literal path segment is `.` or `..`; encoded variants are not decoded. |
| `query_length` | Number of code points in the parsed query, excluding `?`. |
| `query_parameter_count` | Number of nonempty `&`-separated query components; no semantic form interpretation is attempted. |
| `has_fragment` | One when the parsed URL has a nonempty fragment. |

Malformed inputs still produce a feature vector for unit-test safety, but the API separately rejects empty, unsupported-scheme, or hostless inputs. Feature extraction has no classifier verdict on its own. A long raw string is processed linearly; the API imposes an 8,192-character URL limit and a 16,384-byte request-body limit.
