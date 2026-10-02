"""
Backend configuration must actually read the environment and .env file.

Regression guard. CybogBackendSettings used to extend pydantic.BaseModel with
`env_file` in its ConfigDict. `env_file` is a BaseSettings feature, so on a
plain BaseModel the key was inert: no environment variable was read, backend/.env
was never loaded, and every setting silently fell back to its hardcoded default.
CYBOG_OUTPUT_ROOT was logged at startup while having no effect at all, and
config.yaml's relative `output.root` resolved against the process working
directory — so assessments were written wherever the server happened to be
launched from.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _settings_value(env: dict) -> str:
    """Read CYBOG_OUTPUT_ROOT in a fresh interpreter, as a running server would."""
    code = textwrap.dedent(
        """
        from app.config import get_settings
        print(get_settings().CYBOG_OUTPUT_ROOT)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(BACKEND),
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_settings_reads_a_real_environment_variable():
    """The defect: the env var was ignored entirely."""
    override = "/tmp/cybog-env-override-check"
    assert _settings_value({"CYBOG_OUTPUT_ROOT": override}) == override


def test_settings_fall_back_to_dotenv_without_an_env_var():
    """backend/.env must supply a value when no real env var is present."""
    env = {k: v for k, v in os.environ.items() if k != "CYBOG_OUTPUT_ROOT"}
    value = _settings_value(env)
    # A non-empty, absolute path — either from .env or the field default, but
    # never empty and never a bare relative path.
    assert value, "CYBOG_OUTPUT_ROOT must resolve to a value"
    assert os.path.isabs(value), f"expected an absolute root, got {value!r}"


def test_settings_class_supports_env_file():
    """Guard the root cause directly: it must be a BaseSettings."""
    from app.config import CybogBackendSettings

    fields = CybogBackendSettings.model_fields
    assert "env_file" in CybogBackendSettings.model_config, (
        "env_file must be configured for .env loading to work"
    )
    assert "CYBOG_OUTPUT_ROOT" in fields
    assert "CYBOG_CONFIG_PATH" in fields


def test_service_uses_the_configured_output_root():
    """get_cybog_service must apply the override, not just log it."""
    import app.config as app_config
    from app.api.routes import get_cybog_service

    original = app_config.settings.CYBOG_OUTPUT_ROOT
    try:
        app_config.settings.CYBOG_OUTPUT_ROOT = "/tmp/cybog-service-root-check"
        service = get_cybog_service()
        assert str(service.config.output.root) == "/tmp/cybog-service-root-check"
    finally:
        app_config.settings.CYBOG_OUTPUT_ROOT = original
