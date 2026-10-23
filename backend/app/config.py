from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Security Review Tool v01 (Learning)"
    DEBUG: bool = True

    # LLM
    LLM_PROVIDER: str = "anthropic"  # "anthropic" | "openai" | "none"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "claude-3-haiku-20240307"

    # Scanner simulation mode.
    # False (default) = run whatever real engines are installed + the built-in
    #                   HTTP assessment (which is pure Python and always runs).
    # True            = skip all real work and return the simulated fixtures.
    SIMULATE_SCANNERS: bool = False

    # Paths
    UPLOAD_DIR: str = "data/uploads"
    REPORTS_DIR: str = "data/reports"

    # External AI engines
    REDTEAM_DIR: str = "vendor/ai-red-teaming"   # votal-ai-hq/ai-red-teaming checkout
    STRIX_CMD: str = "strix"

    # Decepticon agentic runtime (BitterSecurity/Decepticon). When reachable,
    # engagements are handed to its agent runtime; when not, the native
    # OPPLAN engine below drives the engagement itself.
    DECEPTICON_RUNTIME_URL: str = ""
    DECEPTICON_TIMEOUT: int = 600

    # Engine execution limits (seconds)
    SCANNER_TIMEOUT: int = 300          # long-running DAST engines (zap, strix)
    FAST_SCANNER_TIMEOUT: int = 120     # nuclei / nikto / semgrep / trivy / nmap
    HTTP_PROBE_TIMEOUT: int = 10        # per-request timeout for the built-in checks
    MAX_PARALLEL_ENGINES: int = 4

    # Built-in HTTP assessment scope
    HTTP_PROBE_PATHS: list[str] = [
        "/.git/HEAD",
        "/.env",
        "/server-status",
        "/actuator/env",
        "/backup.zip",
        "/swagger.json",
    ]

    # Security
    MAX_FILE_SIZE_MB: int = 50

    # Supabase (PostgREST) persistence for scan history.
    SUPABASE_URL: str = ""
    SUPABASE_SERVICE_KEY: str = ""

    # Additional CORS origins for the deployed frontend (comma separated)
    CORS_EXTRA_ORIGINS: str = ""
    ALLOWED_EXTENSIONS: list[str] = [".py", ".js", ".ts", ".java", ".go", ".zip", ".tar.gz"]

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
