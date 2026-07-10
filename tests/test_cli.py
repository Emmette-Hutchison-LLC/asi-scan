from typer.testing import CliRunner

from asi_scan.cli import app

runner = CliRunner()


def test_self_test_scan_reports_vulnerabilities_and_exits_nonzero():
    result = runner.invoke(app, ["scan", "--target", "self-test", "--format", "json"])
    assert result.exit_code == 1  # vulnerabilities found in the mock
    assert "asi02.unauth_invoke" in result.stdout


def test_remote_target_requires_authorization():
    result = runner.invoke(app, ["scan", "--target", "https://example.com/mcp"])
    assert result.exit_code != 0
    assert "authorize" in result.stdout.lower()


def test_invalid_format_exits_with_usage_error_not_vulnerability_exit_code():
    result = runner.invoke(app, ["scan", "--target", "self-test", "--format", "xml"])
    assert result.exit_code == 2
