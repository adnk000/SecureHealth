import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def can_user_read(user_clearance, record_label):
    # Bell-LaPadula: No Read-Up
    return user_clearance >= record_label

def mask_name(name):
    # Data Loss Prevention
    parts = name.split()
    masked_parts = [p[0] + "****" for p in parts]
    return " ".join(masked_parts)