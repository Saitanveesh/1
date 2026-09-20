from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "windows" / "mon-windows-service.ps1"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def test_windows_service_lifecycle_script_is_repo_owned() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'ValidateSet("install", "start", "status", "stop", "uninstall")' in script
    assert "MONWindows.exe" in script
    assert "service-run" in script
    assert "--service-name $ServiceName" in script
    assert "Get-Service -Name $Name -ErrorAction SilentlyContinue" in script


def test_windows_service_install_rolls_back_partial_registration() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "$created = $false" in script
    assert "$created = $true" in script
    assert "sc.exe delete $ServiceName" in script
    assert 'Wait-ServiceState -Name $ServiceName -DesiredState "Deleted"' in script


def test_windows_service_lifecycle_does_not_put_secrets_on_command_line() -> None:
    script = SCRIPT.read_text(encoding="utf-8").lower()

    assert "password" not in script
    assert "token" not in script
    assert "secret" not in script
    assert "certificate" not in script


def test_windows_ci_uses_repository_lifecycle_script() -> None:
    workflow = CI.read_text(encoding="utf-8")

    assert "tools\\windows\\mon-windows-service.ps1 install" in workflow
    assert "tools\\windows\\mon-windows-service.ps1 start" in workflow
    assert "tools\\windows\\mon-windows-service.ps1 status" in workflow
    assert "tools\\windows\\mon-windows-service.ps1 stop" in workflow
    assert "tools\\windows\\mon-windows-service.ps1 uninstall" in workflow
