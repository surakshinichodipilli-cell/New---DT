import unittest

from security.url_scanner import analyze_url, normalize_url


class URLScannerTests(unittest.TestCase):
    def test_normalizes_scheme_and_reports_rule_baseline(self):
        result = analyze_url("example.com")
        self.assertEqual(result["url"], "https://example.com")
        self.assertEqual(result["risk_level"], "SAFE")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["analysis_mode"], "transparent rule-based baseline")
        self.assertEqual(analyze_url("HTTP://example.com")["url"], "HTTP://example.com")

    def test_detects_ip_http_and_phishing_indicators(self):
        result = analyze_url("http://127.0.0.1/login")
        self.assertIn("HTTP connection instead of HTTPS", result["detected_indicators"])
        self.assertIn("IP address used as hostname", result["detected_indicators"])
        self.assertEqual(result["risk_level"], "SUSPICIOUS")

    def test_detects_shortener_by_hostname(self):
        result = analyze_url("https://bit.ly/abc")
        self.assertIn("URL shortener detected", result["detected_indicators"])
        self.assertNotIn("URL shortener detected", analyze_url("https://notbit.ly.example/")["detected_indicators"])

    def test_rejects_missing_or_credential_bearing_urls(self):
        with self.assertRaises(ValueError):
            normalize_url("")
        with self.assertRaises(ValueError):
            normalize_url(["https://example.com"])
        with self.assertRaises(ValueError):
            analyze_url("https://user:password@example.com")
        with self.assertRaises(ValueError):
            analyze_url("http://example.com:bad")

    def test_rejects_whitespace_and_overlong_urls(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com/path with space")
        with self.assertRaises(ValueError):
            analyze_url("https://" + ("a" * 2042))


if __name__ == "__main__":
    unittest.main()
