from __future__ import annotations

import json
import os
import threading
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Protocol

import jwt
from fastapi import Depends, HTTPException, WebSocketException, status
from jwt import PyJWTError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from starlette.requests import HTTPConnection


class Role(StrEnum):
    PLATFORM_ADMIN = "platform_admin"
    TENANT_ADMIN = "tenant_admin"
    SOC_ANALYST = "soc_analyst"
    VIEWER = "viewer"
    SITE_CONTROLLER = "site_controller"


class Permission(StrEnum):
    VIEW = "view"
    INGEST = "ingest"
    CONFIGURE = "configure"
    RESPOND = "respond"
    APPROVE_RESPONSE = "approve_response"
    SITE_COMMAND = "site_command"


_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.PLATFORM_ADMIN: {
        Permission.VIEW,
        Permission.INGEST,
        Permission.CONFIGURE,
        Permission.RESPOND,
        Permission.APPROVE_RESPONSE,
        Permission.SITE_COMMAND,
    },
    Role.TENANT_ADMIN: {
        Permission.VIEW,
        Permission.CONFIGURE,
        Permission.RESPOND,
        Permission.APPROVE_RESPONSE,
    },
    Role.SOC_ANALYST: {Permission.VIEW, Permission.RESPOND},
    Role.VIEWER: {Permission.VIEW},
    Role.SITE_CONTROLLER: {Permission.INGEST, Permission.SITE_COMMAND},
}


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=128)
    roles: set[Role] = Field(min_length=1)
    site_ids: set[str] = Field(default_factory=set)

    @model_validator(mode="after")
    def validate_scope(self) -> Principal:
        if Role.PLATFORM_ADMIN in self.roles:
            return self
        if not self.tenant_id:
            raise ValueError("non-platform principals require tenant_id")
        if Role.SITE_CONTROLLER in self.roles and not self.site_ids:
            raise ValueError("site_controller principals require at least one site_id")
        return self

    @property
    def permissions(self) -> set[Permission]:
        permissions: set[Permission] = set()
        for role in self.roles:
            permissions.update(_ROLE_PERMISSIONS[role])
        return permissions


class AuthConfigurationError(RuntimeError):
    pass


class InvalidCredentials(ValueError):
    pass


class TokenAuthenticator(Protocol):
    def verify(self, token: str) -> Principal: ...


def _decode_principal(
    token: str,
    *,
    key: object,
    issuer: str,
    audience: str,
    algorithms: tuple[str, ...],
    leeway_seconds: int,
) -> Principal:
    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=list(algorithms),
            issuer=issuer,
            audience=audience,
            leeway=leeway_seconds,
            options={"require": ["exp", "iat", "sub"]},
        )
        roles = claims.get("roles")
        site_ids = claims.get("site_ids", [])
        if not isinstance(roles, list) or not all(isinstance(item, str) for item in roles):
            raise InvalidCredentials("roles claim must be a list of strings")
        if not isinstance(site_ids, list) or not all(
            isinstance(item, str) for item in site_ids
        ):
            raise InvalidCredentials("site_ids claim must be a list of strings")

        return Principal(
            subject=str(claims["sub"]),
            tenant_id=claims.get("tenant_id"),
            roles=set(roles),
            site_ids=set(site_ids),
        )
    except (PyJWTError, ValidationError, KeyError, TypeError, InvalidCredentials) as exc:
        raise InvalidCredentials("invalid authentication token") from exc


class JWTAuthenticator:
    """Single-key compatibility authenticator."""

    def __init__(
        self,
        public_key_pem: str,
        issuer: str,
        audience: str,
        *,
        algorithms: tuple[str, ...] = ("RS256",),
        leeway_seconds: int = 30,
    ) -> None:
        self.public_key_pem = public_key_pem
        self.issuer = issuer
        self.audience = audience
        self.algorithms = algorithms
        self.leeway_seconds = leeway_seconds

    def verify(self, token: str) -> Principal:
        return _decode_principal(
            token,
            key=self.public_key_pem,
            issuer=self.issuer,
            audience=self.audience,
            algorithms=self.algorithms,
            leeway_seconds=self.leeway_seconds,
        )


class JWKSAuthenticator:
    """Rotatable public-key trust set loaded from inline JSON or an atomically replaced file."""

    _SUPPORTED_ALGORITHMS = frozenset({"RS256"})
    _PRIVATE_RSA_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_json: str | None = None,
        jwks_file: str | Path | None = None,
        algorithms: tuple[str, ...] = ("RS256",),
        leeway_seconds: int = 30,
    ) -> None:
        if bool(jwks_json) == bool(jwks_file):
            raise AuthConfigurationError(
                "configure exactly one JWKS source: inline JSON or a JWKS file"
            )
        if not algorithms or not set(algorithms).issubset(self._SUPPORTED_ALGORITHMS):
            raise AuthConfigurationError("JWKS authentication currently supports RS256 only")

        self.issuer = issuer
        self.audience = audience
        self.algorithms = algorithms
        self.leeway_seconds = leeway_seconds
        self._inline = jwks_json
        self._path = Path(jwks_file) if jwks_file is not None else None
        self._lock = threading.RLock()
        self._source_version: tuple[int, int, int] | None = None
        self._keys: dict[str, jwt.PyJWK] = {}

        if self._inline is not None:
            self._keys = self._parse_jwks(self._inline)
        else:
            self._reload_file_if_needed(force=True)

    def _parse_jwks(self, raw: str) -> dict[str, jwt.PyJWK]:
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthConfigurationError("JWKS source is not valid JSON") from exc
        if not isinstance(document, dict):
            raise AuthConfigurationError("JWKS source must be a JSON object")
        keys = document.get("keys")
        if not isinstance(keys, list) or not keys:
            raise AuthConfigurationError("JWKS source must contain at least one key")
        if len(keys) > 64:
            raise AuthConfigurationError("JWKS source contains too many keys")

        parsed: dict[str, jwt.PyJWK] = {}
        for item in keys:
            if not isinstance(item, dict):
                raise AuthConfigurationError("each JWKS key must be an object")
            if item.get("kty") != "RSA":
                raise AuthConfigurationError("JWKS authentication accepts RSA public keys only")
            if self._PRIVATE_RSA_FIELDS.intersection(item):
                raise AuthConfigurationError(\n                    "JWKS must contain public keys, not RSA private material"\n                )

            kid = item.get("kid")
            if not isinstance(kid, str) or not kid.strip() or len(kid) > 256:
                raise AuthConfigurationError("each JWKS key requires a non-empty kid")
            kid = kid.strip()
            if kid in parsed:
                raise AuthConfigurationError("JWKS contains a duplicate kid")

            declared_alg = item.get("alg")
            if declared_alg is not None and declared_alg not in self.algorithms:
                raise AuthConfigurationError("JWKS key declares an unsupported algorithm")
            public_use = item.get("use")
            if public_use is not None and public_use != "sig":
                raise AuthConfigurationError("JWKS key use must be sig when supplied")
            key_ops = item.get("key_ops")
            if key_ops is not None and (
                not isinstance(key_ops, list) or "verify" not in key_ops
            ):
                raise AuthConfigurationError("JWKS key_ops must permit verify when supplied")

            try:
                parsed_key = jwt.PyJWK.from_dict(item)
            except (PyJWTError, ValueError, TypeError) as exc:
                raise AuthConfigurationError("JWKS contains an invalid RSA public key") from exc
            if parsed_key.algorithm_name not in self.algorithms:
                raise AuthConfigurationError("JWKS key resolves to an unsupported algorithm")
            parsed[kid] = parsed_key
        return parsed

    def _reload_file_if_needed(self, *, force: bool = False) -> None:
        if self._path is None:
            return
        try:
            stat_result = self._path.stat()
            version = (
                int(stat_result.st_ino),
                int(stat_result.st_size),
                int(stat_result.st_mtime_ns),
            )
        except OSError as exc:
            raise AuthConfigurationError("JWKS file is unavailable") from exc

        if not force and version == self._source_version:
            return

        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuthConfigurationError("JWKS file is unreadable") from exc

        parsed = self._parse_jwks(raw)
        self._keys = parsed
        self._source_version = version

    def _key_for_token(self, token: str) -> jwt.PyJWK:
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise InvalidCredentials("invalid authentication token") from exc

        algorithm = header.get("alg")
        if algorithm not in self.algorithms:
            raise InvalidCredentials("invalid authentication token")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidCredentials("invalid authentication token")

        with self._lock:
            self._reload_file_if_needed()
            selected = self._keys.get(kid)
        if selected is None or selected.algorithm_name != algorithm:
            raise InvalidCredentials("invalid authentication token")
        return selected

    def verify(self, token: str) -> Principal:
        selected = self._key_for_token(token)
        return _decode_principal(
            token,
            key=selected.key,
            issuer=self.issuer,
            audience=self.audience,
            algorithms=self.algorithms,
            leeway_seconds=self.leeway_seconds,
        )


def _read_public_key() -> str:
    inline = os.environ.get("MON_AUTH_PUBLIC_KEY_PEM", "").strip()
    path_value = os.environ.get("MON_AUTH_PUBLIC_KEY_FILE", "").strip()
    if inline and path_value:
        raise AuthConfigurationError(
            "configure only one of MON_AUTH_PUBLIC_KEY_PEM or MON_AUTH_PUBLIC_KEY_FILE"
        )
    if inline:
        return inline.replace("\\n", "\n")
    if path_value:
        try:
            return Path(path_value).read_text(encoding="utf-8")
        except OSError as exc:
            raise AuthConfigurationError("MON_AUTH_PUBLIC_KEY_FILE is unreadable") from exc
    raise AuthConfigurationError(
        "configure a JWKS source or MON_AUTH_PUBLIC_KEY_PEM/MON_AUTH_PUBLIC_KEY_FILE"
    )


@lru_cache(maxsize=1)
def get_authenticator() -> TokenAuthenticator:
    issuer = os.environ.get("MON_AUTH_ISSUER", "").strip()
    audience = os.environ.get("MON_AUTH_AUDIENCE", "").strip()
    if not issuer or not audience:
        raise AuthConfigurationError(
            "MON_AUTH_ISSUER and MON_AUTH_AUDIENCE must be configured"
        )

    jwks_inline = os.environ.get("MON_AUTH_JWKS_JSON", "").strip()
    jwks_file = os.environ.get("MON_AUTH_JWKS_FILE", "").strip()
    public_key_inline = os.environ.get("MON_AUTH_PUBLIC_KEY_PEM", "").strip()
    public_key_file = os.environ.get("MON_AUTH_PUBLIC_KEY_FILE", "").strip()

    if jwks_inline and jwks_file:
        raise AuthConfigurationError(
            "configure only one of MON_AUTH_JWKS_JSON or MON_AUTH_JWKS_FILE"
        )
    if (jwks_inline or jwks_file) and (public_key_inline or public_key_file):
        raise AuthConfigurationError(
            "JWKS and legacy single-key authentication cannot be configured together"
        )

    if jwks_inline or jwks_file:
        return JWKSAuthenticator(
            issuer=issuer,
            audience=audience,
            jwks_json=jwks_inline or None,
            jwks_file=jwks_file or None,
        )

    return JWTAuthenticator(
        public_key_pem=_read_public_key(),
        issuer=issuer,
        audience=audience,
    )


def clear_authenticator_cache() -> None:
    get_authenticator.cache_clear()


def _extract_token(connection: HTTPConnection) -> str | None:
    authorization = connection.headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.casefold() == "bearer" and value.strip():
        return value.strip()

    cookie = connection.cookies.get("mon_session")
    if cookie:
        return cookie
    return None


def _raise_auth_error(connection: HTTPConnection, *, unavailable: bool = False) -> None:
    if connection.scope.get("type") == "websocket":
        raise WebSocketException(
            code=1011 if unavailable else 1008,
            reason="authentication unavailable" if unavailable else "authentication required",
        )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE
        if unavailable
        else status.HTTP_401_UNAUTHORIZED,
        detail="authentication unavailable" if unavailable else "authentication required",
        headers=None if unavailable else {"WWW-Authenticate": "Bearer"},
    )


async def get_principal(connection: HTTPConnection) -> Principal:
    token = _extract_token(connection)
    if not token:
        _raise_auth_error(connection)

    try:
        authenticator = get_authenticator()
        return authenticator.verify(token)
    except AuthConfigurationError:
        _raise_auth_error(connection, unavailable=True)
    except InvalidCredentials:
        _raise_auth_error(connection)

    raise RuntimeError("unreachable authentication state")


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def is_scope_authorized(
    principal: Principal,
    tenant_id: str,
    site_id: str | None,
    permission: Permission,
) -> bool:
    if permission not in principal.permissions:
        return False

    if Role.PLATFORM_ADMIN in principal.roles:
        return True

    if principal.tenant_id != tenant_id:
        return False

    return not (
        site_id is not None
        and principal.site_ids
        and site_id not in principal.site_ids
    )


def require_scope(
    principal: Principal,
    tenant_id: str,
    site_id: str | None,
    permission: Permission,
) -> None:
    if not is_scope_authorized(principal, tenant_id, site_id, permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="principal is not authorized for this tenant/site operation",
        )
