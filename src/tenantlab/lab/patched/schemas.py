"""Request validation and response shapes for the patched API (docs/api-contract.md s10).

Request bodies are parsed strictly (D-30) and only AFTER the gates. A validation error reports
locations and codes, never the offending value; the name of an unknown key is not echoed either.
Response models forbid extra fields, so adding a field is a visible change that the oracle-driven
property tests (TL-09) must agree with.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime
from typing import Annotated, Any, Final, Literal, NoReturn
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)
from pydantic_core import PydanticCustomError

from tenantlab.auth.policy import Role
from tenantlab.schemas.errors import MAX_FIELD_ERRORS, FieldError

MAX_VERSION: Final = 2_147_483_647  # fits a 32-bit integer column on every database
TITLE_MIN: Final = 1
TITLE_MAX: Final = 120
# Characters that can make a title display as something it is not (Trojan Source, RLO spoofing).
_BIDI_CONTROLS: Final = frozenset(chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
# The roles that may see `owner_principal_id` on a project (field_policy.csv: floor editor).
OWNER_FIELD_ROLES: Final = frozenset({Role.OWNER, Role.ADMIN, Role.EDITOR})


class BodyError(Exception):
    """The body (or its media type) is unusable. Carries only locations and codes."""

    def __init__(self, errors: tuple[FieldError, ...]) -> None:
        super().__init__("invalid body")
        self.errors = errors


def _fail(loc: tuple[str, ...], code: str) -> NoReturn:
    raise BodyError((FieldError(loc=loc, code=code),))


def _check_media_type(content_type: str | None) -> None:
    if content_type is None:
        _fail(("header", "content-type"), "unsupported_media_type")
    media, *params = (part.strip() for part in content_type.split(";"))
    if media.lower() != "application/json":
        _fail(("header", "content-type"), "unsupported_media_type")
    for param in params:
        name, _, value = param.partition("=")
        if name.strip().lower() != "charset" or value.strip().strip('"').lower() != "utf-8":
            _fail(("header", "content-type"), "unsupported_media_type")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(_name: str) -> NoReturn:
    raise ValueError("NaN and Infinity are not JSON")


def parse_json_object(raw: bytes, content_type: str | None) -> dict[str, Any]:
    """Media type, UTF-8, JSON syntax and 'a single object'. Raises BodyError."""
    _check_media_type(content_type)
    if not raw.strip():
        _fail(("body",), "empty_body")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail(("body",), "invalid_utf8")
    try:
        value = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError
        _fail(("body",), "invalid_json")
    if not isinstance(value, dict):
        _fail(("body",), "not_an_object")
    return value


def field_errors(exc: ValidationError) -> tuple[FieldError, ...]:
    """Pydantic errors reduced to {loc, code}. An unknown key's NAME is attacker-chosen text, so it
    is reported as one generic `unknown_field` at the body."""
    out: list[FieldError] = []
    for item in exc.errors(include_url=False, include_context=False, include_input=False):
        if item["type"] == "extra_forbidden":
            error = FieldError(loc=("body",), code="unknown_field")
        else:
            loc = tuple(str(p) if isinstance(p, str) else p for p in item["loc"])[:8]
            error = FieldError(loc=loc or ("body",), code=item["type"])
        if error not in out:
            out.append(error)
    return tuple(out[:MAX_FIELD_ERRORS])


def _check_title(value: str) -> str:
    if not TITLE_MIN <= len(value) <= TITLE_MAX:
        raise PydanticCustomError("title_length", "title must be 1 to 120 characters")
    for char in value:
        if unicodedata.category(char) in ("Cc", "Cs") or char in _BIDI_CONTROLS:
            raise PydanticCustomError("title_characters", "title contains a forbidden character")
    return value


Title = Annotated[str, AfterValidator(_check_title)]
Version = Annotated[int, Field(ge=1, le=MAX_VERSION)]
ProjectStatus = Literal["draft", "active", "archived"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class CreateProject(_Body):
    title: Title
    market: str


class PatchProject(_Body):
    title: Title | None = None
    status: ProjectStatus | None = None
    row_version: Version

    @model_validator(mode="after")
    def _something_to_change(self) -> PatchProject:
        if self.title is None and self.status is None:
            raise PydanticCustomError("nothing_to_change", "give a title or a status")
        return self


class PutMembership(_Body):
    role: Literal["owner", "admin", "editor", "viewer"]
    status: Literal["active", "revoked"]
    version: Version


# ------------------------------------------------------------------------------ responses ----
class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProjectListItem(_Out):
    id: UUID
    tenant_id: UUID
    market: str
    title: str
    status: str
    row_version: int


class ContactPublic(_Out):
    id: UUID
    public_name: str


class ProjectDetail(ProjectListItem):
    contacts: list[ContactPublic]


class ProjectDetailWithOwner(ProjectDetail):
    owner_principal_id: UUID


class ContactPrivate(_Out):
    id: UUID
    public_name: str
    email_private: str
    phone_private: str


class InvoiceDetail(_Out):
    id: UUID
    tenant_id: UUID
    project_id: UUID
    amount_minor: int
    currency: str
    status: str


class MembershipDetail(_Out):
    principal_id: UUID
    tenant_id: UUID
    role: str
    status: str
    version: int


class AuditItem(_Out):
    id: int
    actor_id: UUID | None
    tenant_id: UUID | None
    action: str
    resource_type: str
    resource_id: UUID | None
    decision: str
    reason_code: str
    timestamp: datetime
    correlation_id: UUID


def page(items: list[BaseModel], next_cursor: str | None, total: int) -> dict[str, Any]:
    return {
        "items": [item.model_dump(mode="json") for item in items],
        "next_cursor": next_cursor,
        "total": total,
    }
