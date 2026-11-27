"""Production entry point used by Render's Gunicorn web server."""

from database import init_db

# Render's free service has an ephemeral filesystem. Seed a fresh synthetic
# database whenever its instance starts; keep local app.py startup unchanged.
init_db()

from app import app

