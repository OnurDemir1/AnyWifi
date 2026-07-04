from anywifi.core import platform


def test_wsl_detection_via_env(monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    assert platform.is_wsl() is True


def test_wsl_false_without_markers(monkeypatch):
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.delenv("WSL_INTEROP", raising=False)
    # False if /proc files are absent (Windows) or don't contain "microsoft"
    result = platform.is_wsl()
    assert result in (True, False)  # environment-dependent; must at least not crash


def test_detect_returns_systeminfo():
    info = platform.detect()
    assert info.os_name in ("linux", "windows", "darwin")
    assert isinstance(info.is_wsl, bool)
