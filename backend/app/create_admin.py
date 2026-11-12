
from getpass import getpass

from sqlalchemy.exc import IntegrityError

from app.database import Base, engine, SessionLocal
from app.models import User
from app.security import hash_password


def create_admin():
    # Ensure database tables exist
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        print("\n=== REEMSEC DataGuard | Admin Setup ===\n")

        username = input("Admin username: ").strip()
        email = input("Admin email: ").strip().lower()

        if not username or not email:
            print("Username and email are required.")
            return

        existing_user = (
            db.query(User)
            .filter(
                (User.username == username)
                | (User.email == email)
            )
            .first()
        )

        if existing_user:
            print("A user with this username or email already exists.")
            return

        password = getpass("Admin password: ")
        confirm_password = getpass("Confirm password: ")

        if password != confirm_password:
            print("Passwords do not match.")
            return

        if len(password) < 12:
            print("Password must be at least 12 characters long.")
            return

        admin = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )

        db.add(admin)
        db.commit()

        print("\nAdmin account created successfully!")
        print(f"Username: {username}")
        print(f"Email: {email}")
        print("Role: admin")

    except IntegrityError:
        db.rollback()
        print("Could not create admin. Username or email may already exist.")

    except Exception as error:
        db.rollback()
        print(f"An error occurred: {error}")

    finally:
        db.close()


if __name__ == "__main__":
    create_admin()
