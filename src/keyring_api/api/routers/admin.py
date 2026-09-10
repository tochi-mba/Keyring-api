"""The administrative surface.

Two ways to authorise a request here, and the difference matters:

* **A role.** The normal path. An account holding a role that contains the permission a
  route requires. Every action is recorded in the audit log against that account.
* **The break-glass token.** The recovery path, for when no owner can log in or none
  exists. It holds every permission and is recorded as ``break-glass``, conspicuously.

Every route states its permission in its own signature via ``requires(...)``, so the
requirement is visible in the OpenAPI document and next to the handler rather than buried
in one. The service checks again -- both, deliberately: the route dependency is the one a
reader sees, and the service check is the one that still holds when a handler is called
from somewhere else.

**Permission is checked before existence, everywhere.** A caller without the permission
gets 403 for an account that exists and 403 for one that does not, so the difference
between 403 and 404 cannot be used to enumerate account ids.

**Nothing here returns a credential.** There is no permission that would allow it and no
model that could carry it. Administration means managing accounts, not becoming them.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response, status

from keyring_api.admin.service import Actor
from keyring_api.api.dependencies import ActorDep, ContainerDep, requires
from keyring_api.api.schemas.admin import (
    AccountListResponse,
    AccountSummary,
    AuditEntryResponse,
    AuditListResponse,
    PermissionInfo,
    PermissionListResponse,
    ProfileSummary,
    RoleListResponse,
    RoleResponse,
    SetRolesRequest,
    SetStatusRequest,
    UpdateRoleRequest,
    WriteRoleRequest,
)
from keyring_api.api.schemas.auth import InviteResponse, IssueInviteRequest
from keyring_api.api.schemas.common import Problem
from keyring_api.domain.accounts import Account
from keyring_api.domain.profiles import Profile
from keyring_api.domain.rbac import Permission, Role

router = APIRouter(prefix="/v1/admin", tags=["admin"])

MAX_AUDIT_PAGE = 1000
"""Ceiling on one page of audit entries, so a response stays a predictable size."""

_PROBLEM: dict[str, Any] = {"model": Problem}
_DENIED: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {"model": Problem, "description": "No valid session."},
    status.HTTP_403_FORBIDDEN: {
        "model": Problem,
        "description": (
            "Authenticated, but lacking the permission this route requires. Checked "
            "before the target is looked up, so this answer is the same whether or not "
            "the target exists."
        ),
    },
}
_NOT_FOUND: dict[int | str, dict[str, Any]] = {status.HTTP_404_NOT_FOUND: {"model": Problem}}

PERMISSION_DESCRIPTIONS = {
    Permission.ACCOUNTS_READ: "List accounts and read one. Metadata only.",
    Permission.ACCOUNTS_INVITE: "Mint invites for new accounts.",
    Permission.ACCOUNTS_DISABLE: "Disable or re-enable an account, ending its sessions.",
    Permission.ACCOUNTS_DELETE: "Delete an account and everything it owns. Irreversible.",
    Permission.ACCOUNTS_REVOKE_SESSIONS: "Sign an account out everywhere.",
    Permission.ACCOUNTS_RESET_PASSWORD: (
        "Mint a password reset for somebody else. Close to an account takeover, so it is "
        "separate from disabling."
    ),
    Permission.ROLES_READ: "See which roles exist and what they allow.",
    Permission.ROLES_WRITE: (
        "Create, edit and delete custom roles, bounded by your own permissions."
    ),
    Permission.ROLES_ASSIGN: "Grant and revoke roles, bounded by your own permissions.",
    Permission.PROFILES_READ_ANY: (
        "See which profiles and connections another account has. Metadata only -- there "
        "is deliberately no permission that returns another account's credential."
    ),
    Permission.PROFILES_DELETE_ANY: "Delete another account's profile. Destroys, never reads.",
    Permission.AUDIT_READ: "Read the record of privileged actions.",
}


def render_account(account: Account, *, now_locked: bool) -> AccountSummary:
    """Turn an account into its administrative wire form. Carries no password material."""
    return AccountSummary(
        account_id=account.account_id,
        email=account.email,
        status=account.status,
        roles=list(account.roles),
        created_at=account.created_at,
        updated_at=account.updated_at,
        locked=now_locked,
    )


def render_role(role: Role) -> RoleResponse:
    """Turn a role into its wire form, with permissions sorted for stable output."""
    return RoleResponse(
        name=role.name,
        description=role.description,
        permissions=sorted(permission.value for permission in role.permissions),
        builtin=role.builtin,
        created_at=role.created_at,
        updated_at=role.updated_at,
    )


# -- Permissions and roles -------------------------------------------------------------


@router.get(
    "/permissions",
    operation_id="list_permissions",
    summary="List every permission a role can contain",
    description=(
        "The full vocabulary, so an administrator building a custom role can see what is "
        "available rather than guessing at strings. Note what is absent: there is no "
        "permission that returns another account's credential, by design."
    ),
    response_model=PermissionListResponse,
    dependencies=[Depends(requires(Permission.ROLES_READ))],
    responses={**_DENIED},
)
async def list_permissions() -> PermissionListResponse:
    """Every permission this service understands."""
    return PermissionListResponse(
        permissions=[
            PermissionInfo(name=permission.value, description=PERMISSION_DESCRIPTIONS[permission])
            for permission in sorted(Permission, key=lambda item: item.value)
        ]
    )


@router.get(
    "/roles",
    operation_id="list_roles",
    summary="List roles and what each one allows",
    description=(
        "Built-in roles first, then custom ones. Built-in roles cannot be edited or "
        "deleted, so `member` always means what it says."
    ),
    response_model=RoleListResponse,
    responses={**_DENIED},
)
async def list_roles(container: ContainerDep, actor: ActorDep) -> RoleListResponse:
    """Every role."""
    roles = await container.admin_service.list_roles(actor)
    return RoleListResponse(roles=[render_role(role) for role in roles])


@router.post(
    "/roles",
    operation_id="create_role",
    summary="Define a custom role",
    description=(
        "Creates a role with exactly the permissions you list. You cannot include a "
        "permission you do not hold yourself -- otherwise defining a role would be a way "
        "to acquire one. An unrecognised permission is rejected rather than ignored."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=RoleResponse,
    responses={
        **_DENIED,
        status.HTTP_409_CONFLICT: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
    },
)
async def create_role(
    body: WriteRoleRequest, container: ContainerDep, actor: ActorDep
) -> RoleResponse:
    """Define a new role."""
    role = await container.admin_service.create_role(
        actor, name=body.name, permissions=body.permissions, description=body.description
    )
    return render_role(role)


@router.put(
    "/roles/{name}",
    operation_id="update_role",
    summary="Replace a custom role's permissions",
    description=(
        "Replaces the permission set entirely. Built-in roles are immutable: editing "
        "`member` into something powerful would be the quietest possible privilege "
        "escalation, since nobody's roles would have changed. Takes effect on every "
        "holder's next request."
    ),
    response_model=RoleResponse,
    responses={**_DENIED, **_NOT_FOUND, status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM},
)
async def update_role(
    name: str, body: UpdateRoleRequest, container: ContainerDep, actor: ActorDep
) -> RoleResponse:
    """Change what a role allows."""
    role = await container.admin_service.update_role(
        actor, name, permissions=body.permissions, description=body.description
    )
    return render_role(role)


@router.delete(
    "/roles/{name}",
    operation_id="delete_role",
    summary="Delete a custom role nobody holds",
    description=(
        "Refuses while any account still holds it: silently stripping a permission from "
        "everybody who had it is the kind of change nobody notices until somebody cannot "
        "do their job. Revoke it from each account first. Built-in roles cannot be "
        "deleted."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**_DENIED, **_NOT_FOUND, status.HTTP_409_CONFLICT: _PROBLEM},
)
async def delete_role(name: str, container: ContainerDep, actor: ActorDep) -> Response:
    """Remove a custom role."""
    await container.admin_service.delete_role(actor, name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# -- Accounts --------------------------------------------------------------------------


@router.get(
    "/accounts",
    operation_id="list_accounts",
    summary="List every account",
    description=(
        "Address, status, roles and timestamps. No password material and no credentials "
        "-- there is no administrative route in this service that returns either."
    ),
    response_model=AccountListResponse,
    responses={**_DENIED},
)
async def list_accounts(container: ContainerDep, actor: ActorDep) -> AccountListResponse:
    """Every account."""
    accounts = await container.admin_service.list_accounts(actor)
    now = container.clock.now()
    return AccountListResponse(
        accounts=[
            render_account(account, now_locked=account.is_locked(now=now)) for account in accounts
        ]
    )


@router.get(
    "/accounts/{account_id}",
    operation_id="get_account",
    summary="Read one account",
    description=(
        "Responds 403 without the permission and 404 with it, in that order -- so the "
        "difference cannot be used to discover which account ids exist."
    ),
    response_model=AccountSummary,
    responses={**_DENIED, **_NOT_FOUND},
)
async def get_account(account_id: str, container: ContainerDep, actor: ActorDep) -> AccountSummary:
    """One account."""
    account = await container.admin_service.get_account(actor, account_id)
    return render_account(account, now_locked=account.is_locked(now=container.clock.now()))


@router.put(
    "/accounts/{account_id}/roles",
    operation_id="set_account_roles",
    summary="Replace an account's roles",
    description=(
        "Sets the complete set of roles this account holds. You cannot grant a role whose "
        "permissions exceed your own, including to yourself -- otherwise assigning roles "
        "would be a way to acquire every permission. Refuses to remove the last owner: a "
        "deployment with no owner cannot appoint one. Takes effect on that account's very "
        "next request."
    ),
    response_model=AccountSummary,
    responses={
        **_DENIED,
        **_NOT_FOUND,
        status.HTTP_409_CONFLICT: {
            "model": Problem,
            "description": "This would leave the deployment with no owner.",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
    },
)
async def set_account_roles(
    account_id: str, body: SetRolesRequest, container: ContainerDep, actor: ActorDep
) -> AccountSummary:
    """Replace an account's roles."""
    account = await container.admin_service.set_account_roles(actor, account_id, body.roles)
    return render_account(account, now_locked=account.is_locked(now=container.clock.now()))


@router.put(
    "/accounts/{account_id}/status",
    operation_id="set_account_status",
    summary="Disable or re-enable an account",
    description=(
        "Disabling stops new logins **and** ends every live session -- otherwise the "
        "person just disabled stays signed in wherever they already are, which is the "
        "one thing disabling is for. Reversible, unlike deletion."
    ),
    response_model=AccountSummary,
    responses={**_DENIED, **_NOT_FOUND},
)
async def set_account_status(
    account_id: str, body: SetStatusRequest, container: ContainerDep, actor: ActorDep
) -> AccountSummary:
    """Disable or re-enable an account."""
    account = await container.admin_service.set_status(actor, account_id, body.status)
    return render_account(account, now_locked=account.is_locked(now=container.clock.now()))


@router.post(
    "/accounts/{account_id}/revoke-sessions",
    operation_id="revoke_account_sessions",
    summary="Sign an account out everywhere",
    description=(
        "The gentler answer to a lost laptop: ends every session without disabling the "
        "account or touching its password, so the person can simply log in again."
    ),
    response_model=dict,
    responses={**_DENIED, **_NOT_FOUND},
)
async def revoke_account_sessions(
    account_id: str, container: ContainerDep, actor: ActorDep
) -> dict[str, int]:
    """End every session for an account."""
    return {"revoked": await container.admin_service.revoke_sessions(actor, account_id)}


@router.post(
    "/accounts/{account_id}/password-reset",
    operation_id="issue_account_password_reset",
    summary="Mint a password reset for somebody else",
    description=(
        "For a person who cannot get in. Its own permission, separate from disabling, "
        "because whoever holds the token sets the password -- so this is close to an "
        "account takeover, and a role can reasonably have one power without the other. "
        "The token is emailed when mail is configured; otherwise it is returned here."
    ),
    response_model=InviteResponse,
    responses={**_DENIED, **_NOT_FOUND, status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM},
)
async def issue_account_password_reset(
    account_id: str, container: ContainerDep, actor: ActorDep
) -> InviteResponse:
    """Mint a reset token for another account."""
    grant = await container.admin_service.issue_password_reset(actor, account_id)
    delivered = container.account_service.delivers_email
    return InviteResponse(
        grant_id=grant.grant_id,
        expires_at=grant.expires_at,
        delivered=delivered,
        token=None if delivered else grant.token,
    )


@router.delete(
    "/accounts/{account_id}",
    operation_id="delete_account",
    summary="Delete an account and everything it owns",
    description=(
        "Removes the account, every session, every outstanding invite and reset, every "
        "profile, and every stored credential -- nothing is left that could authenticate "
        "as them or be decrypted later. Third-party grants are not revoked at the "
        "providers; tell the person to do that too. Refuses to delete the last owner. "
        "Irreversible."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        **_DENIED,
        **_NOT_FOUND,
        status.HTTP_409_CONFLICT: {
            "model": Problem,
            "description": "This is the last owner; appoint another first.",
        },
    },
)
async def delete_account(account_id: str, container: ContainerDep, actor: ActorDep) -> Response:
    """Delete an account and cascade."""
    await container.admin_service.delete_account(actor, account_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# -- Other accounts' profiles ----------------------------------------------------------


@router.get(
    "/accounts/{account_id}/profiles",
    operation_id="list_account_profiles",
    summary="See which services an account has connected",
    description=(
        "Metadata only, and that asymmetry is the point: an administrator can see that "
        "somebody's connection has expired without being able to use it. There is no "
        "permission in this service that returns another account's credential."
    ),
    response_model=list[ProfileSummary],
    responses={**_DENIED, **_NOT_FOUND},
)
async def list_account_profiles(
    account_id: str, container: ContainerDep, actor: ActorDep
) -> list[ProfileSummary]:
    """Another account's profiles."""
    profiles = await container.admin_service.list_profiles(actor, account_id)
    return [_render_profile(profile) for profile in profiles]


@router.delete(
    "/accounts/{account_id}/profiles/{name}",
    operation_id="delete_account_profile",
    summary="Delete another account's profile",
    description=(
        "For cleaning up after somebody who has left. Destroys the profile and the "
        "credentials in it; it does not read them, and cleaning up after someone should "
        "not require the ability to use what they left behind."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**_DENIED, **_NOT_FOUND},
)
async def delete_account_profile(
    account_id: str, name: str, container: ContainerDep, actor: ActorDep
) -> Response:
    """Delete another account's profile."""
    await container.admin_service.delete_profile(actor, account_id, name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# -- Invites and audit -----------------------------------------------------------------


@router.post(
    "/invites",
    operation_id="issue_invite",
    summary="Mint an invite for a new account",
    description=(
        "There is no public registration, so this is the only way an account comes into "
        "existence. The first account ever created becomes the owner; every one after "
        "that gets `member`, which has no administrative permissions. If mail is "
        "configured the invite is emailed and `token` is omitted."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=InviteResponse,
    responses={
        **_DENIED,
        status.HTTP_409_CONFLICT: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
    },
)
async def issue_invite(
    body: IssueInviteRequest, container: ContainerDep, actor: ActorDep
) -> InviteResponse:
    """Mint a single-use invite."""
    return await _invite(container, actor, body.email)


@router.get(
    "/audit",
    operation_id="read_audit_log",
    summary="Read the record of privileged actions",
    description=(
        "Who did what to whom, newest first. Actions on your own account are not "
        "recorded; actions taken *on another account* always are. Entries carry opaque "
        "account ids rather than addresses, and never contain a secret."
    ),
    response_model=AuditListResponse,
    responses={**_DENIED},
)
async def read_audit_log(
    container: ContainerDep,
    actor: ActorDep,
    # Bounded at both ends. Without a lower bound a negative limit reaches a negative
    # slice and returns every entry *except* the oldest -- not a leak, since the caller
    # already holds audit:read, but a page that quietly means something else.
    limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_PAGE)] = 100,
) -> AuditListResponse:
    """Recent privileged actions."""
    entries = await container.admin_service.read_audit(actor, limit=limit)
    return AuditListResponse(
        entries=[
            AuditEntryResponse(
                entry_id=entry.entry_id,
                at=entry.at,
                action=entry.action,
                actor_id=entry.actor_id,
                target_id=entry.target_id,
                detail=entry.detail,
            )
            for entry in entries
        ]
    )


async def _invite(container: ContainerDep, actor: Actor, email: str) -> InviteResponse:
    """Shared by the role-authorised and break-glass invite routes."""
    grant = await container.admin_service.invite(actor, email=email)
    delivered = container.account_service.delivers_email
    return InviteResponse(
        grant_id=grant.grant_id,
        expires_at=grant.expires_at,
        delivered=delivered,
        token=None if delivered else grant.token,
    )


def _render_profile(profile: Profile) -> ProfileSummary:
    """A profile as an administrator sees it: names and states, never values."""
    return ProfileSummary(
        name=profile.name,
        connections=[
            {
                "service": connection.service,
                "kind": connection.kind.value,
                "status": connection.status.value,
            }
            for connection in sorted(profile.connections, key=lambda item: item.service)
        ],
    )
