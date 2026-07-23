from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable, Iterable
from urllib.parse import SplitResult, parse_qsl, urlsplit, urlunsplit

from .errors import fail


_PERCENT_RE = re.compile(r"%(?![0-9A-F]{2})")
_ASCII_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_Resolver = Callable[..., list[tuple[Any, ...]]]


@dataclass(frozen=True)
class NormalizedUrl:
    value: str
    host: str
    port: int
    scheme: str


def canonical_host(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid")
    value = value.rstrip(".").lower()
    if not value or ".." in value or "%" in value or "\\" in value:
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid")
    try:
        canonical = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid") from exc
    labels = canonical.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid")
    return canonical


def normalize_url(value: str, *, allow_http: bool = False) -> NormalizedUrl:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8", errors="strict")) > 8192
        or _ASCII_CONTROL_RE.search(value) is not None
        or "\\" in value
        or _PERCENT_RE.search(value) is not None
    ):
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid")
    try:
        value.encode("ascii", errors="strict")
        split = urlsplit(value)
    except (UnicodeError, ValueError) as exc:
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid") from exc
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if split.scheme.lower() not in allowed_schemes or not split.netloc:
        raise fail("ECO_RESEARCH_SCHEME_DENIED", "Research URL scheme is denied")
    if split.username is not None or split.password is not None or split.fragment:
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid")
    try:
        raw_host = split.hostname
        raw_port = split.port
    except ValueError as exc:
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid") from exc
    if raw_host is None or ":" in raw_host:
        # IPv6 literals are deliberately out of this minimal production profile.
        raise fail("ECO_RESEARCH_URL_INVALID", "Research URL is invalid")
    host = canonical_host(raw_host)
    scheme = split.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    port = raw_port or default_port
    if scheme == "https" and port != 443:
        raise fail("ECO_RESEARCH_PORT_DENIED", "Research URL port is denied")
    if scheme == "http" and not allow_http:
        raise fail("ECO_RESEARCH_SCHEME_DENIED", "Research URL scheme is denied")
    path = split.path or "/"
    netloc = host if port == default_port else f"{host}:{port}"
    canonical = urlunsplit(SplitResult(scheme, netloc, path, split.query, ""))
    return NormalizedUrl(canonical, host, port, scheme)


def host_allowed(host: str, rules: Iterable[dict[str, Any]]) -> bool:
    canonical = canonical_host(host)
    for rule in rules:
        allowed = rule["host"]
        if canonical == allowed:
            return True
        if rule["includeSubdomains"] and canonical.endswith("." + allowed):
            return True
    return False


def validate_url_query(url: str, *, allowed_keys: Iterable[str]) -> None:
    """Enforce an exact credential-free query-key allowlist without exposing values."""

    allowed = frozenset(allowed_keys)
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise fail("ECO_RESEARCH_URL_QUERY_DENIED", "Research URL query is denied") from exc
    keys = [key for key, _ in pairs]
    sensitive = re.compile(
        r"(?:^|[._-])(auth|authorization|credential|key|password|secret|signature|token)(?:$|[._-])"
    )
    if (
        len(keys) != len(set(keys))
        or any(key not in allowed or sensitive.search(key.lower()) for key in keys)
    ):
        raise fail("ECO_RESEARCH_URL_QUERY_DENIED", "Research URL query is denied")


def _ip_is_public(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def resolve_public_addresses(host: str, *, resolver: _Resolver = socket.getaddrinfo) -> tuple[str, ...]:
    canonical = canonical_host(host)
    if canonical == "localhost" or canonical.endswith(".localhost"):
        raise fail("ECO_RESEARCH_NETWORK_TARGET_DENIED", "Research network target is denied")
    try:
        literal = ipaddress.ip_address(canonical)
    except ValueError:
        literal = None
    if literal is not None:
        if not _ip_is_public(str(literal)):
            raise fail("ECO_RESEARCH_NETWORK_TARGET_DENIED", "Research network target is denied")
        return (str(literal),)
    try:
        answers = resolver(canonical, 443, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise fail("ECO_RESEARCH_DNS_FAILED", "Research target resolution failed") from exc
    addresses = sorted({str(item[4][0]) for item in answers if len(item) >= 5})
    if not addresses or any(not _ip_is_public(item) for item in addresses):
        raise fail("ECO_RESEARCH_NETWORK_TARGET_DENIED", "Research network target is denied")
    return tuple(addresses)
