from __future__ import annotations

import os
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

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


_ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.PLATFORM_ADMIN: {
        Permission.VIEW,
        Permission.INGEST,
        Permission.CONFIGURE,
        Permission.RESPOND,
    },
    Role.TENANT_ADMIN: {
        Permission.VIEW,
        Permission.CONFIGURE,
        Permission.RESPOND,
    },
    Role.SOC_ANALYST: {Permission.VIEW, Permission.RESPOND},
    Role.VIEWER: {Permission.VIEW},
    Role.SITE_CONTROLLER: {Permission.INGEST},
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


class JWTAuthenticator:
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
        try:
            claims = jwt.decode(
                token,
                key=self.public_key_pem,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway_seconds,
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


def _read_public_key() -> str:
    inline = os.environ.get("MON_AUTH_PUBLIC_KEY_PEM", "").strip()
    if inline:
        return inline.replace("\\n", "\n")

    path_value = os.environ.get("MON_AUTH_PUBLIC_KEY_FILE", "").strip()
    if path_value:
        return Path(path_value).read_text(encoding="utf-8")

    raise AuthConfigurationError(
        "MON_AUTH_PUBLIC_KEY_PEM or MON_AUTH_PUBLIC_KEY_FILE must be configured"
    )


@lru_cache(maxsize=1)
def get_authenticator() -> JWTAuthenticator:
    issuer = os.environ.get("MON_AUTH_ISSUER", "").strip()
    audience = os.environ.get("MON_AUTH_AUDIENCE", "").strip()
    if not issuer or not audience:
        raise AuthConfigurationError(
            "MON_AUTH_ISSUER and MON_AUTH_AUDIENCE must be configured"
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
    except AuthConfigurationError:
        _raise_auth_error(connection, unavailable=True)

    try:
        return authenticator.verify(token)
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
