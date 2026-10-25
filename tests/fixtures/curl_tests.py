"""Public behavior tests for curl."""

from unittest.mock import MagicMock, patch

from pydantic import TypeAdapter

from tests.fixtures.curl import curl_request, curl_request_with_headers


class TestCurlRequest:
    """Tests for curl_request helper function."""

    def test_returns_status_code(self) -> None:
        """Should parse and return HTTP status code from curl output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="200", stderr="", returncode=0)
            result = curl_request("http://example.com/", 8080)
            assert result == 200

    def test_returns_zero_on_non_numeric_output(self) -> None:
        """Should return 0 when curl output is not a valid status code."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="error", returncode=0)
            result = curl_request("http://example.com/", 8080)
            assert result == 0

    def test_passes_custom_headers(self) -> None:
        """Should include custom headers in curl command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="200", stderr="", returncode=0)
            _ = curl_request(
                "http://example.com/",
                8080,
                headers={"Authorization": "Bearer token"},
            )
            cmd = TypeAdapter(list[str]).validate_python(mock_run.call_args[0][0])
            assert "-H" in cmd
            idx = cmd.index("-H")
            assert cmd[idx + 1] == "Authorization: Bearer token"

    def test_clears_no_proxy_env(self) -> None:
        """Should clear no_proxy and NO_PROXY in the environment."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="200", stderr="", returncode=0)
            _ = curl_request("http://example.com/", 8080)
            env = TypeAdapter(dict[str, str]).validate_python(
                mock_run.call_args[1]["env"]
            )
            assert env["no_proxy"] == ""
            assert env["NO_PROXY"] == ""

    def test_uses_proxy_argument(self) -> None:
        """Should use the proxy port in the curl command."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="200", stderr="", returncode=0)
            _ = curl_request("http://example.com/", 9090)
            cmd = TypeAdapter(list[str]).validate_python(mock_run.call_args[0][0])
            assert "-x" in cmd
            idx = cmd.index("-x")
            assert "9090" in cmd[idx + 1]


class TestCurlRequestWithHeaders:
    """Tests for curl_request_with_headers helper function."""

    def test_returns_status_code_and_headers(self) -> None:
        """Should parse status code, headers, and body from curl output."""
        output = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
            status, headers, body = curl_request_with_headers(
                "http://example.com/", 8080
            )
            assert status == 200
            assert "content-type" in headers
            assert headers["content-type"] == "text/plain"
            assert "OK" in body

    def test_returns_zero_on_empty_output(self) -> None:
        """Should return 0 status when curl returns empty output."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
            status, headers, _body = curl_request_with_headers(
                "http://example.com/", 8080
            )
            assert status == 0
            assert headers == {}

    def test_parses_multiple_headers(self) -> None:
        """Should correctly parse multiple response headers."""
        output = (
            "HTTP/1.1 407 Proxy Authentication Required\r\n"
            + 'Proxy-Authenticate: Basic realm="proxy"\r\n'
            + "Connection: close\r\n"
            + "\r\n"
            + ""
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
            status, headers, _body = curl_request_with_headers(
                "http://example.com/", 8080
            )
            assert status == 407
            assert "proxy-authenticate" in headers
            assert "connection" in headers

    def test_includes_custom_headers(self) -> None:
        """Should include custom headers in curl command."""
        output = "HTTP/1.1 200 OK\r\n\r\nOK"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
            _ = curl_request_with_headers(
                "http://example.com/",
                8080,
                headers={"Proxy-Authorization": "Basic YWRtaW46c2VjcmV0"},
            )
            cmd = TypeAdapter(list[str]).validate_python(mock_run.call_args[0][0])
            assert "-H" in cmd
            idx = cmd.index("-H")
            assert "Proxy-Authorization" in cmd[idx + 1]

    def test_clears_no_proxy_env(self) -> None:
        """Should clear no_proxy and NO_PROXY in the environment."""
        output = "HTTP/1.1 200 OK\r\n\r\nOK"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
            _ = curl_request_with_headers("http://example.com/", 8080)
            env = TypeAdapter(dict[str, str]).validate_python(
                mock_run.call_args[1]["env"]
            )
            assert env["no_proxy"] == ""
            assert env["NO_PROXY"] == ""
