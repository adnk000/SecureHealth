import hashlib
import hmac

from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password):
    """Create a salted scrypt password hash using Werkzeug."""
    return generate_password_hash(password, method="scrypt")


def verify_password(stored_hash, password):
    """
    Verify current Werkzeug hashes and transparently migrate old SHA-256 hashes.
    Returns (is_valid, needs_upgrade).
    """
    if not stored_hash:
        return False, False

    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, password), False

    # Backward compatibility for accounts created by the previous application.
    legacy_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if hmac.compare_digest(stored_hash, legacy_hash):
        return True, True

    return False, False


def can_user_read(user_clearance, record_label):
    """Bell-LaPadula simple security property: no read up."""
    try:
        return int(user_clearance) >= int(record_label)
    except (TypeError, ValueError):
        return False


def mask_name(name):
    """Mask names for users with the lowest clearance."""
    if not name:
        return ""
    return " ".join(part[0] + "****" for part in name.split() if part)
