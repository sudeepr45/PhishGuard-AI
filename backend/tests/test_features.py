from backend.src.features import FEATURE_NAMES, extract_url_features


def test_extracts_documented_string_only_signals():
    features = extract_url_features("https://a-b.example.com/a/../login?x=1&y=2#frag")
    assert tuple(features) == FEATURE_NAMES
    assert features["uses_https"] == 1
    assert features["hostname_dot_count"] == 2
    assert features["subdomain_count"] == 1
    assert features["hyphen_count"] == 1
    assert features["path_has_dot_segment"] == 1
    assert features["query_parameter_count"] == 2
    assert features["has_fragment"] == 1


def test_empty_and_malformed_values_are_safe():
    empty = extract_url_features("")
    malformed = extract_url_features("http://[broken%zz")
    assert all(isinstance(value, int) for value in empty.values())
    assert all(isinstance(value, int) for value in malformed.values())
    assert empty["url_length"] == 0


def test_unicode_and_exceptionally_long_strings_are_deterministic():
    url = "https://例え.テスト/путь?x=%E2%9C%93"
    assert extract_url_features(url) == extract_url_features(url)
    long_url = "https://example.com/" + "x" * 1_000_000
    features = extract_url_features(long_url)
    assert features["url_length"] == len(long_url)
    assert features["path_length"] == len(long_url) - len("https://example.com")


def test_malformed_and_valid_percent_encodings_are_distinguished():
    features = extract_url_features("https://example.com/%2f/%zz/%")
    assert features["percent_encoding_count"] == 1
    assert features["malformed_percent_count"] == 2


def test_ip_hostname_and_at_sign_are_observable_only():
    features = extract_url_features("https://user@example.com@192.0.2.1/path")
    assert features["is_ip_hostname"] == 1
    assert features["authority_has_at_sign"] == 1

