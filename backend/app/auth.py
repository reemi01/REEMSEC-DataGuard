
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security import (
    oauth2_scheme,
    verify_password,
    create_access_token,
    decode_access_token,
)
from app.services.audit_service import log_action


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    user_id = decode_access_token(token)

    if user_id is None:
        raise credentials_error

    user = db.query(User).filter(User.id == user_id).first()

    if user is None or not user.is_active:
        raise credentials_error

    return user


@router.post("/login")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    identifier = form_data.username.strip()

    user = db.query(User).filter(
        (User.username == identifier) |
        (User.email == identifier)
    ).first()

    ip_address = (
        request.client.host
        if request.client
        else None
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(
            form_data.password,
            user.password_hash if user else ""
        )
    ):
        try:
            log_action(
                db=db,
                action="LOGIN_FAILED",
                resource_type="auth",
                details={
                    "reason": "Invalid credentials or inactive account"
                },
                ip_address=ip_address,
            )
            db.commit()
        except Exception:
            db.rollback()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        log_action(
            db=db,
            user_id=user.id,
            action="LOGIN_SUCCESS",
            resource_type="auth",
            resource_id=str(user.id),
            details={
                "role": user.role,
            },
            ip_address=ip_address,
        )

        db.commit()

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to complete login.",
        )

    access_token = create_access_token(user.id)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
        },
    }


@router.get("/me")
def get_my_profile(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at,
    }
