from .config import app
from .routes_auth import auth_bp
from .routes_assets import assets_bp
from flask import redirect, url_for

# -------------------------------------------------
# Main Application Entry Point (app.py)
# -------------------------------------------------
# This file is named 'app.py' to serve as the entry point 
# for production servers like Gunicorn (gunicorn app:app).

# Register Blueprints
app.register_blueprint(auth_bp, url_prefix='/')
app.register_blueprint(assets_bp, url_prefix='/')

# Default Index Route
@app.route("/")
def index():
    # Redirects to the main assets list (which will force login if unauthenticated)
    return redirect(url_for('assets.index')) 

if __name__ == '__main__':
    # Run in debug mode locally
    app.run(debug=True)
