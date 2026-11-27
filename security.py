from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    """Hash a password using Werkzeug's scrypt-based password hashing."""
    return generate_password_hash(password, method="scrypt")

def verify_password(stored_hash, password):
    """Verify modern hashes and support one-time migration from legacy SHA-256."""
    import hashlib
    import hmac

    if not stored_hash:
        return False, False

    # Modern Werkzeug hashes are self-describing (e.g. scrypt:...).
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, password), False

    # Legacy compatibility: old versions stored an unsalted SHA-256 digest.
    legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
    if hmac.compare_digest(stored_hash, legacy):
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
