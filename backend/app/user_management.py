
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.permissions import require_admin
from app.security import hash_password
from app.services.audit_service import log_action


router = APIRouter(
    prefix="/admin/users",
    tags=["User Management"],
)


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "employee"


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None


def format_user(user: User):
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def get_ip_address(request: Request):
    return request.client.host if request.client else None


# Create User
@router.post("/")
def create_user(
    data: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    username = data.username.strip()
    email = str(data.email).strip().lower()

    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must contain at least 3 characters.",
        )

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise HTTPException(
            status_code=400,
            detail="Username contains invalid characters.",
        )

    if len(data.password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 12 characters.",
        )

    allowed_roles = [
        "admin",
        "security_analyst",
        "employee",
    ]

    if data.role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail="Invalid user role.",
        )

    existing_user = db.query(User).filter(
        (User.username == username) |
        (User.email == email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists.",
        )

    new_user = User(
        username=username,
        email=email,
        password_hash=hash_password(data.password),
        role=data.role,
        is_active=True,
    )

    try:
        db.add(new_user)
        db.flush()

        log_action(
            db=db,
            user_id=current_admin.id,
            action="USER_CREATED",
            resource_type="user",
            resource_id=str(new_user.id),
            details={
                "username": new_user.username,
                "role": new_user.role,
            },
            ip_address=get_ip_address(request),
        )

        db.commit()
        db.refresh(new_user)

        return format_user(new_user)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to create user.",
        )


# List Users
@router.get("/")
def list_users(
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .all()
    )

    return {
        "total_users": len(users),
        "users": [
            format_user(user)
            for user in users
        ],
    }


# Update User
@router.patch("/{user_id}")
def update_user(
    user_id: int,
    data: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided.",
        )

    if "role" in updates:
        if updates["role"] not in [
            "admin",
            "security_analyst",
            "employee",
        ]:
            raise HTTPException(
                status_code=400,
                detail="Invalid user role.",
            )

    if user.id == current_admin.id:
        if updates.get("is_active") is False:
            raise HTTPException(
                status_code=400,
                detail="You cannot deactivate your own account.",
            )

        if (
            "role" in updates
            and updates["role"] != "admin"
        ):
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own admin role.",
            )

    new_role = updates.get("role", user.role)
    new_active_status = updates.get(
        "is_active",
        user.is_active,
    )

    if (
        user.role == "admin"
        and user.is_active
        and (
            new_role != "admin"
            or new_active_status is False
        )
    ):
        active_admins = db.query(User).filter(
            User.role == "admin",
            User.is_active.is_(True),
        ).count()

        if active_admins <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove or deactivate the last active administrator.",
            )

    changes = {}

    if "role" in updates and updates["role"] != user.role:
        changes["role"] = {
            "old": user.role,
            "new": updates["role"],
        }
        user.role = updates["role"]

    if (
        "is_active" in updates
        and updates["is_active"] != user.is_active
    ):
        changes["is_active"] = {
            "old": user.is_active,
            "new": updates["is_active"],
        }
        user.is_active = updates["is_active"]

    if not changes:
        return format_user(user)

    try:
        log_action(
            db=db,
            user_id=current_admin.id,
            action="USER_UPDATED",
            resource_type="user",
            resource_id=str(user.id),
            details={
                "target_username": user.username,
                "changes": changes,
            },
            ip_address=get_ip_address(request),
        )

        db.commit()
        db.refresh(user)

        return format_user(user)

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to update user.",
        )


# Delete User
@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    if user.id == current_admin.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account.",
        )

    if user.role == "admin" and user.is_active:
        active_admins = db.query(User).filter(
            User.role == "admin",
            User.is_active.is_(True),
        ).count()

        if active_admins <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last active administrator.",
            )

    target_username = user.username
    target_role = user.role

    try:
        log_action(
            db=db,
            user_id=current_admin.id,
            action="USER_DELETED",
            resource_type="user",
            resource_id=str(user.id),
            details={
                "username": target_username,
                "role": target_role,
                "note": "The user's scan records are deleted; audit history is retained.",
            },
            ip_address=get_ip_address(request),
        )

        # SQLAlchemy cascades the user's scans and findings.
        # Related audit logs are retained with a null user reference.
        db.delete(user)
        db.commit()

        return {
            "message": "User deleted successfully.",
            "deleted_user_id": user_id,
            "deleted_username": target_username,
        }

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to delete user.",
        )
