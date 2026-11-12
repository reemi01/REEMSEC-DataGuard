
from fastapi import Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User


def require_roles(*allowed_roles: str):
    """
    Restrict an endpoint to specific user roles.
    """

    def role_checker(
        current_user: User = Depends(get_current_user),
    ):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )

        return current_user

    return role_checker


# Role dependencies
require_admin = require_roles("admin")

require_analyst_or_admin = require_roles(
    "admin",
    "security_analyst",
)

require_any_authenticated_user = require_roles(
    "admin",
    "security_analyst",
    "employee",
)
