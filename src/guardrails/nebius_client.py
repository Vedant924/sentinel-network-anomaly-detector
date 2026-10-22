"""Nebius Token Factory client for NVIDIA open model analysis."""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

DEFAULT_NEBIUS_BASE_URL = "https://api.tokenfactory.nebius.com/v1"

# Unverified default: Model IDs on dynamic inference platforms can vary.
# Users should verify available model IDs via GET /v1/models or their project dashboard.
# Overridable via NEBIUS_MODEL environment variable or constructor argument.
DEFAULT_NEBIUS_MODEL = "nvidia/Nemotron-3_5-Lightning"

# Maximum response size accepted from the remote API (1 MB).
# Note: This bounds in-memory response buffering; it does not protect against
# all transport-layer Denial-of-Service or resource-exhaustion scenarios.
MAX_RESPONSE_BYTES = 1024 * 1024

# Explicit Model Statuses
STATUS_MODEL_OK = "MODEL_OK"
STATUS_MODEL_MOCK = "MODEL_MOCK"
STATUS_MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"

# Generic, fixed error codes to prevent information leakage
ERROR_HTTP = "HTTP_ERROR"
ERROR_NETWORK = "NETWORK_ERROR"
ERROR_INVALID_RESPONSE = "INVALID_RESPONSE"
ERROR_RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
ERROR_UNEXPECTED = "UNEXPECTED_CLIENT_ERROR"


class NebiusClient:
    """Client for querying NVIDIA open models on Nebius Token Factory.

    Uses standard library urllib.request to maintain zero external dependencies.
    Provides automatic fallback to an offline mock mode when credentials are absent
    or when network errors occur.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 10.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        raw_key = api_key if api_key is not None else os.getenv("NEBIUS_API_KEY")
        if raw_key is not None and not isinstance(raw_key, str):
            raise ValueError("API key must be a string or None.")
        self.api_key = raw_key.strip() if raw_key and raw_key.strip() else None

        raw_base_url = (
            base_url
            if base_url is not None
            else os.getenv("NEBIUS_BASE_URL", DEFAULT_NEBIUS_BASE_URL)
        )
        self.allow_insecure_localhost = (
            allow_insecure_localhost
            or os.getenv("NEBIUS_ALLOW_INSECURE_LOCALHOST", "").lower() in ("1", "true", "yes")
        )
        self.base_url = self._validate_base_url(raw_base_url, self.allow_insecure_localhost)

        raw_model = model if model is not None else os.getenv("NEBIUS_MODEL", DEFAULT_NEBIUS_MODEL)
        if not isinstance(raw_model, str) or not raw_model.strip():
            raise ValueError("Model ID must be a non-empty string.")
        self.model = raw_model.strip()

        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("Timeout must be a positive number.")
        self.timeout = float(timeout)

    @staticmethod
    def _validate_base_url(url: str, allow_insecure_localhost: bool = False) -> str:
        """Validate base URL structure, scheme, and security."""
        if not isinstance(url, str) or not url.strip():
            raise ValueError("Base URL must be a non-empty string.")

        cleaned = url.strip().rstrip("/")
        parsed = urllib.parse.urlsplit(cleaned)

        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Base URL is malformed; missing scheme or host.")

        if parsed.fragment:
            raise ValueError("Base URL must not contain a URL fragment.")

        if parsed.username or parsed.password:
            raise ValueError("Base URL must not contain embedded user credentials.")

        if parsed.scheme == "https":
            return cleaned
        elif parsed.scheme == "http":
            hostname = (parsed.hostname or "").lower()
            if allow_insecure_localhost and hostname in ("localhost", "127.0.0.1", "::1"):
                return cleaned
            raise ValueError(
                "Base URL must use HTTPS. Insecure HTTP is only permitted for localhost "
                "when explicitly enabled via allow_insecure_localhost."
            )
        else:
            raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only HTTPS is permitted.")

    @property
    def is_configured(self) -> bool:
        """Return True if a non-empty, non-whitespace API key is available."""
        return bool(self.api_key)

    def analyze_incident(
        self,
        prompt: str,
        system_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request advisory analysis from the NVIDIA model via Nebius.

        Returns a structured dictionary containing model analysis or an offline mock.
        Model output is strictly advisory narrative metadata for audit logs and analysts.
        It NEVER directly grants execution permissions or dispatches tools.
        """
        if not self.is_configured:
            return self._mock_analysis(
                prompt, reason="No NEBIUS_API_KEY configured (offline mock mode)."
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "Sentinel-AI-Guard/1.0",
        }

        system_instruction = (
            system_context
            or "You are an AI safety analyst. Evaluate the security risk of the provided user input "
            "and explain your assessment concisely."
        )

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 256,
            "temperature": 0.1,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(endpoint, data=req_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                # Bounded read to avoid unbounded response body memory consumption
                resp_bytes = response.read(MAX_RESPONSE_BYTES + 1)
                if len(resp_bytes) > MAX_RESPONSE_BYTES:
                    return {
                        "status": STATUS_MODEL_UNAVAILABLE,
                        "success": False,
                        "is_mock": False,
                        "model": self.model,
                        "explanation": (
                            "[FALLBACK] Model API response exceeded maximum allowable size limit. "
                            "Deterministic guardrails remain authoritative."
                        ),
                        "error": ERROR_RESPONSE_TOO_LARGE,
                    }
                try:
                    decoded_str = resp_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return {
                        "status": STATUS_MODEL_UNAVAILABLE,
                        "success": False,
                        "is_mock": False,
                        "model": self.model,
                        "explanation": (
                            "[FALLBACK] Model API returned invalid non-UTF-8 response. "
                            "Deterministic guardrails remain authoritative."
                        ),
                        "error": ERROR_INVALID_RESPONSE,
                    }
                data = json.loads(decoded_str)

            # Deep response schema validation
            if not isinstance(data, dict):
                raise ValueError("API response root must be a JSON object.")

            choices = data.get("choices")
            if not isinstance(choices, list) or len(choices) == 0:
                raise ValueError("API response missing non-empty 'choices' list.")

            first_choice = choices[0]
            if not isinstance(first_choice, dict):
                raise ValueError("API response 'choices[0]' must be an object.")

            message = first_choice.get("message")
            if not isinstance(message, dict):
                raise ValueError("API response 'choices[0].message' must be an object.")

            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                raise ValueError("API response 'choices[0].message.content' must be a non-empty string.")

            return {
                "status": STATUS_MODEL_OK,
                "success": True,
                "is_mock": False,
                "model": self.model,
                "explanation": content.strip(),
                "error": None,
            }
        except urllib.error.HTTPError as http_err:
            return {
                "status": STATUS_MODEL_UNAVAILABLE,
                "success": False,
                "is_mock": False,
                "model": self.model,
                "explanation": (
                    f"[FALLBACK] Model API returned HTTP {http_err.code}. "
                    "Deterministic guardrails remain authoritative."
                ),
                "error": f"{ERROR_HTTP}_{http_err.code}",
            }
        except urllib.error.URLError:
            return {
                "status": STATUS_MODEL_UNAVAILABLE,
                "success": False,
                "is_mock": False,
                "model": self.model,
                "explanation": (
                    "[FALLBACK] Model API network connection unavailable. "
                    "Deterministic guardrails remain authoritative."
                ),
                "error": ERROR_NETWORK,
            }
        except (KeyError, IndexError, json.JSONDecodeError, ValueError):
            return {
                "status": STATUS_MODEL_UNAVAILABLE,
                "success": False,
                "is_mock": False,
                "model": self.model,
                "explanation": (
                    "[FALLBACK] Malformed response received from model API. "
                    "Deterministic guardrails remain authoritative."
                ),
                "error": ERROR_INVALID_RESPONSE,
            }
        except Exception:
            return {
                "status": STATUS_MODEL_UNAVAILABLE,
                "success": False,
                "is_mock": False,
                "model": self.model,
                "explanation": (
                    "[FALLBACK] Unexpected communication error with model API. "
                    "Deterministic guardrails remain authoritative."
                ),
                "error": ERROR_UNEXPECTED,
            }

    def _mock_analysis(self, prompt: str, reason: str) -> Dict[str, Any]:
        """Return a clearly labeled simulated analysis when offline or without credentials."""
        prompt_len = len(prompt) if isinstance(prompt, str) else 0
        return {
            "status": STATUS_MODEL_MOCK,
            "success": True,
            "is_mock": True,
            "model": f"{self.model} (simulated/offline-mock)",
            "explanation": (
                f"[SIMULATED MOCK] Simulated offline analysis for input ({prompt_len} chars). "
                f"Status: {reason}"
            ),
            "error": None,
        }
