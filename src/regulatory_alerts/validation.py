"""Input validation helpers — URL safety, SSRF prevention, etc."""

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def validate_webhook_url(url: str) -> tuple[bool, str | None]:
    """Validate a webhook URL for safety (SSRF prevention).

    Blocks:
    - Non-HTTP(S) schemes
    - Private/reserved IP ranges (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, etc.)
    - Loopback hostnames (localhost, *.local)
    - URLs without a hostname
    - Cloud metadata endpoints (169.254.169.254)

    Returns:
        (is_valid, error_message). If valid, error_message is None.
    """
    if not url or not url.strip():
        return False, "Webhook URL is required"

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "Invalid URL format"

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        return False, "Webhook URL must use http:// or https://"

    hostname = parsed.hostname
    if not hostname:
        return False, "Webhook URL must include a hostname"

    # Block localhost and local hostnames
    hostname_lower = hostname.lower()
    if hostname_lower in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return False, "Webhook URL cannot target localhost"

    if hostname_lower.endswith(".local") or hostname_lower.endswith(".internal"):
        return False, "Webhook URL cannot target local/internal hosts"

    # Resolve hostname and check if it resolves to a private IP
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        for family, _type, _proto, _canonname, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
                return False, "Webhook URL cannot target private or reserved IP addresses"
    except socket.gaierror:
        # DNS resolution failed — hostname doesn't exist. Allow it through
        # (will fail at delivery time with a clear error, not a security risk).
        pass
    except Exception as e:
        logger.warning("Webhook URL validation error for %s: %s", hostname, e)
        # Don't block on unexpected errors — let it fail at delivery
        pass

    return True, None
