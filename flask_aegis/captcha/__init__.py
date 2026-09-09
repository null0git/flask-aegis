from .base import CaptchaProvider
from .hcaptcha import HcaptchaProvider
from .recaptcha import NullProvider, RecaptchaProvider

_PROVIDERS = {
    "recaptcha": RecaptchaProvider,
    "hcaptcha": HcaptchaProvider,
}


def build_provider(config: dict) -> CaptchaProvider:
    """Instantiate a provider from a plain config dict, e.g. the value
    passed to ``Aegis(app, captcha={...})``."""
    provider_name = config.get("provider")
    if provider_name is None:
        return NullProvider()
    cls = _PROVIDERS.get(provider_name)
    if cls is None:
        raise ValueError(
            f"Unknown captcha provider {provider_name!r}. "
            f"Available: {', '.join(_PROVIDERS)}. "
            "Register custom providers with Aegis.register_provider()."
        )
    kwargs = {k: v for k, v in config.items() if k != "provider"}
    return cls(**kwargs)


def register_provider(name: str, cls) -> None:
    _PROVIDERS[name] = cls


__all__ = [
    "CaptchaProvider", "RecaptchaProvider", "HcaptchaProvider", "NullProvider",
    "build_provider", "register_provider",
]
