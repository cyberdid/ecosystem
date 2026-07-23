from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
import zlib
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Protocol
from urllib.parse import urljoin, urlsplit

from .errors import ResearchToolError, fail
from .url_policy import (
    NormalizedUrl,
    host_allowed,
    normalize_url,
    resolve_public_addresses,
    validate_url_query,
)


@dataclass(frozen=True)
class ResearchTransportPolicy:
    domain_rules: tuple[dict[str, Any], ...]
    max_redirects: int
    max_wire_bytes: int
    max_decoded_bytes: int
    connect_timeout_seconds: float
    read_timeout_seconds: float
    allowed_media_types: frozenset[str]
    allowed_url_query_keys: frozenset[str]


@dataclass(frozen=True)
class TransportResponse:
    body: bytes
    media_type: str
    source_url: str
    final_url: str
    redirect_chain: tuple[str, ...]


class ResearchTransport(Protocol):
    test_only_allow_http: bool

    def request(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        policy: ResearchTransportPolicy,
    ) -> TransportResponse: ...


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        *,
        address: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self._pinned_address = address

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_address, self.port), timeout=self.timeout
        )
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def strict_bounded_json(
    value: bytes,
    *,
    maximum_depth: int = 32,
    maximum_items: int = 10_000,
    maximum_string_bytes: int = 1_048_576,
) -> Any:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = item
        return result

    def reject_constant(_: str) -> None:
        raise ValueError("non-finite value")

    try:
        document = json.loads(
            value.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except (RecursionError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise fail("ECO_RESEARCH_JSON_INVALID", "Research JSON content is invalid") from exc
    stack: list[tuple[Any, int]] = [(document, 1)]
    items = 0
    while stack:
        current, depth = stack.pop()
        if depth > maximum_depth:
            raise fail("ECO_RESEARCH_JSON_LIMIT", "Research JSON content exceeds a structural limit")
        if isinstance(current, dict):
            items += len(current)
            for key, item in current.items():
                if len(key.encode("utf-8")) > maximum_string_bytes:
                    raise fail("ECO_RESEARCH_JSON_LIMIT", "Research JSON content exceeds a structural limit")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            items += len(current)
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str) and len(current.encode("utf-8")) > maximum_string_bytes:
            raise fail("ECO_RESEARCH_JSON_LIMIT", "Research JSON content exceeds a structural limit")
        if items > maximum_items:
            raise fail("ECO_RESEARCH_JSON_LIMIT", "Research JSON content exceeds a structural limit")
    return document


def decode_bounded_entity(
    chunks: Iterable[bytes],
    *,
    content_encoding: str,
    max_wire_bytes: int,
    max_decoded_bytes: int,
) -> bytes:
    """Bound both transfer bytes and decompressed bytes before publication."""

    encoding = content_encoding.strip().lower()
    if encoding in {"", "identity"}:
        decompressor = None
    elif encoding == "gzip":
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decompressor = zlib.decompressobj(zlib.MAX_WBITS)
    else:
        raise fail("ECO_RESEARCH_ENCODING_DENIED", "Research response encoding is denied")
    wire = 0
    decoded = bytearray()
    try:
        for chunk in chunks:
            if not isinstance(chunk, bytes):
                raise fail("ECO_RESEARCH_TRANSPORT_INVALID", "Research transport response is invalid")
            wire += len(chunk)
            if wire > max_wire_bytes:
                raise fail("ECO_RESEARCH_WIRE_LIMIT", "Research response exceeds the wire limit")
            output = chunk if decompressor is None else decompressor.decompress(
                chunk, max_decoded_bytes + 1 - len(decoded)
            )
            decoded.extend(output)
            if len(decoded) > max_decoded_bytes:
                raise fail("ECO_RESEARCH_DECODED_LIMIT", "Research response exceeds the decoded limit")
            if decompressor is not None and decompressor.unconsumed_tail:
                raise fail("ECO_RESEARCH_DECODED_LIMIT", "Research response exceeds the decoded limit")
        if decompressor is not None:
            decoded.extend(decompressor.flush(max_decoded_bytes + 1 - len(decoded)))
            if len(decoded) > max_decoded_bytes:
                raise fail("ECO_RESEARCH_DECODED_LIMIT", "Research response exceeds the decoded limit")
            if not decompressor.eof:
                raise fail("ECO_RESEARCH_ENCODING_INVALID", "Research response encoding is invalid")
    except ResearchToolError:
        raise
    except (OSError, EOFError, zlib.error) as exc:
        raise fail("ECO_RESEARCH_ENCODING_INVALID", "Research response encoding is invalid") from exc
    return bytes(decoded)


class SafeHttpsTransport:
    """Credential-free, proxy-free HTTPS transport with DNS pinning per hop.

    The implementation resolves a host once, rejects the entire answer set if
    any address is non-public, and connects to one exact accepted address while
    preserving TLS hostname verification. This materially narrows SSRF and DNS
    rebinding risk; it is not a universal proof against a compromised resolver,
    kernel, network path, or public service that proxies to private resources.
    """

    test_only_allow_http = False

    def __init__(
        self,
        *,
        resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
        ssl_context: ssl.SSLContext | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._resolver = resolver
        self._context = ssl_context or ssl.create_default_context()
        self._monotonic = monotonic

    def _chunks(
        self,
        response: http.client.HTTPResponse,
        *,
        connection: _PinnedHTTPSConnection,
        deadline: float,
    ) -> Iterable[bytes]:
        while True:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise fail("ECO_RESEARCH_TIMEOUT", "Research request timed out")
            if connection.sock is None:
                raise fail("ECO_RESEARCH_TRANSPORT_FAILED", "Research transport failed")
            connection.sock.settimeout(remaining)
            block = response.read(65_536)
            if not block:
                return
            yield block

    def _connection(
        self, target: NormalizedUrl, *, timeout: float
    ) -> _PinnedHTTPSConnection:
        addresses = resolve_public_addresses(target.host, resolver=self._resolver)
        return _PinnedHTTPSConnection(
            target.host,
            target.port,
            address=addresses[0],
            timeout=timeout,
            context=self._context,
        )

    def request(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        policy: ResearchTransportPolicy,
    ) -> TransportResponse:
        if method not in {"GET", "POST"}:
            raise fail("ECO_RESEARCH_METHOD_DENIED", "Research HTTP method is denied")
        if body is not None and (not isinstance(body, bytes) or len(body) > 65_536):
            raise fail("ECO_RESEARCH_INPUT_LIMIT", "Research request exceeds the input limit")
        if method == "GET" and body is not None:
            raise fail("ECO_RESEARCH_REQUEST_INVALID", "Research request is invalid")
        source = normalize_url(url)
        validate_url_query(source.value, allowed_keys=policy.allowed_url_query_keys)
        if not host_allowed(source.host, policy.domain_rules):
            raise fail("ECO_RESEARCH_DOMAIN_DENIED", "Research target domain is denied")
        current = source
        visited = {source.value}
        redirects: list[str] = []
        deadline = self._monotonic() + policy.read_timeout_seconds

        for _ in range(policy.max_redirects + 1):
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise fail("ECO_RESEARCH_TIMEOUT", "Research request timed out")
            connection: _PinnedHTTPSConnection | None = None
            response: http.client.HTTPResponse | None = None
            try:
                connection = self._connection(
                    current, timeout=min(policy.connect_timeout_seconds, remaining)
                )
                headers = {
                    "Accept": ", ".join(sorted(policy.allowed_media_types)),
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                    "Host": current.host,
                    "User-Agent": "eco-governed-research/1",
                }
                if body is not None:
                    headers["Content-Type"] = "application/json; charset=utf-8"
                    headers["Content-Length"] = str(len(body))
                split = urlsplit(current.value)
                path = split.path or "/"
                if split.query:
                    path += "?" + split.query
                connection.request(method, path or "/", body=body, headers=headers)
                response = connection.getresponse()
                header_bytes = sum(
                    len(name.encode("ascii", errors="ignore"))
                    + len(value.encode("latin-1", errors="ignore"))
                    for name, value in response.getheaders()
                )
                if header_bytes > 32_768:
                    raise fail("ECO_RESEARCH_HEADERS_LIMIT", "Research response headers exceed the limit")
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location:
                        raise fail("ECO_RESEARCH_REDIRECT_INVALID", "Research redirect is invalid")
                    if len(redirects) >= policy.max_redirects:
                        raise fail("ECO_RESEARCH_REDIRECT_LIMIT", "Research redirect limit is exceeded")
                    next_target = normalize_url(urljoin(current.value, location))
                    validate_url_query(
                        next_target.value, allowed_keys=policy.allowed_url_query_keys
                    )
                    if not host_allowed(next_target.host, policy.domain_rules):
                        raise fail("ECO_RESEARCH_REDIRECT_DENIED", "Research redirect target is denied")
                    if next_target.value in visited:
                        raise fail("ECO_RESEARCH_REDIRECT_LOOP", "Research redirect loop is denied")
                    visited.add(next_target.value)
                    redirects.append(next_target.value)
                    current = next_target
                    if response.status == 303:
                        method, body = "GET", None
                    continue
                if response.status != 200:
                    raise fail("ECO_RESEARCH_HTTP_STATUS", "Research endpoint returned a denied status")
                length = response.getheader("Content-Length")
                if length is not None:
                    try:
                        declared_length = int(length)
                    except ValueError as exc:
                        raise fail("ECO_RESEARCH_HEADERS_INVALID", "Research response headers are invalid") from exc
                    if declared_length < 0 or declared_length > policy.max_wire_bytes:
                        raise fail("ECO_RESEARCH_WIRE_LIMIT", "Research response exceeds the wire limit")
                content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                if content_type not in policy.allowed_media_types:
                    raise fail("ECO_RESEARCH_MEDIA_DENIED", "Research response media type is denied")
                decoded = decode_bounded_entity(
                    self._chunks(response, connection=connection, deadline=deadline),
                    content_encoding=response.getheader("Content-Encoding") or "identity",
                    max_wire_bytes=policy.max_wire_bytes,
                    max_decoded_bytes=policy.max_decoded_bytes,
                )
                if not decoded or b"\x00" in decoded:
                    raise fail("ECO_RESEARCH_CONTENT_DENIED", "Research response content is denied")
                try:
                    decoded.decode("utf-8", errors="strict")
                    if content_type == "application/json":
                        strict_bounded_json(decoded)
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                    raise fail("ECO_RESEARCH_CONTENT_INVALID", "Research response content is invalid") from exc
                return TransportResponse(
                    body=decoded,
                    media_type=content_type,
                    source_url=source.value,
                    final_url=current.value,
                    redirect_chain=tuple(redirects),
                )
            except ResearchToolError:
                raise
            except (TimeoutError, socket.timeout) as exc:
                raise fail("ECO_RESEARCH_TIMEOUT", "Research request timed out") from exc
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                raise fail("ECO_RESEARCH_TRANSPORT_FAILED", "Research transport failed") from exc
            finally:
                if response is not None:
                    response.close()
                if connection is not None:
                    connection.close()
        raise fail("ECO_RESEARCH_REDIRECT_LIMIT", "Research redirect limit is exceeded")
