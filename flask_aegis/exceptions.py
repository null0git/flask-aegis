"""
flask_aegis.exceptions
~~~~~~~~~~~~~~~~~~~~~~~

Exception hierarchy for Flask-Aegis.

Keeping a dedicated exception module (instead of scattering ``ValueError``
everywhere) means calling code — and end users of the extension — can
catch specific failure modes without needing to know internal details.
"""


class AegisError(Exception):
    """Base class for all Flask-Aegis errors."""


class ConfigurationError(AegisError):
    """Raised when Aegis is configured in an invalid or unsafe way.

    Examples: unknown profile name, a policy that references a
    non-existent parent, a CAPTCHA provider missing required secrets.
    """


class PolicyNotFoundError(AegisError):
    """Raised when code references a policy name that was never registered."""


class PolicyConflictError(AegisError):
    """Raised when two policy definitions conflict in a way that cannot
    be resolved automatically (e.g. circular inheritance)."""


class RuleError(AegisError):
    """Raised when a security rule fails to execute (a bug in the rule
    itself, not a detection). Rules should never raise on attacker input —
    only on genuine internal errors."""


class CaptchaError(AegisError):
    """Raised for CAPTCHA provider configuration or verification failures
    that are not simply 'the user failed the challenge'."""


class AegisBlocked(AegisError):
    """Internal control-flow exception used to short-circuit a request
    once the decision engine has decided to BLOCK. Flask-Aegis converts
    this into an HTTP response before it reaches the view function; it
    is not intended to be caught by application code."""

    def __init__(self, reason: str, rule_id: str | None = None, status: int = 403):
        super().__init__(reason)
        self.reason = reason
        self.rule_id = rule_id
        self.status = status
