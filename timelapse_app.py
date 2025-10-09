"""Timelapse app with Dropbox OAuth (refresh tokens), per-config app credentials,
and automatic retrying for background uploads.
"""

import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dropbox
import dropbox.exceptions
import dropbox.files
import requests
from dateutil.tz import gettz
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# --- Configuration and Initialization ---
# The database file must be stored on a stateful volume when running in Docker
DB_FILE = "/data/timelapse.db"
DATABASE_URL = f"sqlite://{DB_FILE}"

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

TZ_ENV = os.environ.get("TZ")
if TZ_ENV:
    APP_TIMEZONE = gettz(TZ_ENV)
    if APP_TIMEZONE is None:
        logger.warning(
            f"Invalid TZ environment variable '{TZ_ENV}'. Defaulting to UTC.",
        )
        APP_TIMEZONE = timezone.utc
    else:
        logger.info(f"Application timezone set to: {TZ_ENV}")
else:
    APP_TIMEZONE = timezone.utc
    logger.info("TZ environment variable not set. Defaulting to UTC.")


app = Flask(__name__)
# !! IMPORTANT: Flask requires a secret key for session management !!
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))
if app.secret_key == os.urandom(24):  # Using an ephemeral key if not set
    logger.warning(
        "FLASK_SECRET_KEY environment variable is not set. Using an ephemeral key. This is NOT recommended for production and will cause issues with session persistence (e.g., OAuth flow across restarts).",
    )

CSRF_TOKEN_SESSION_KEY = "csrf_token_session_key"  # noqa: S105

# SQLAlchemy Setup
engine = create_engine(DATABASE_URL)
Base = declarative_base()
# This is the session *factory*
Session = sessionmaker(bind=engine)
# This global instance is used only by the background thread and initialization
db_session = Session()

# Global state for the background service
timelapse_thread = None
stop_event = threading.Event()
# Semaphore to ensure only one thread can start/stop at a time
thread_lock = threading.Lock()

# --- Database Models ---


class Config(Base):
    """Stores the application configuration and state."""

    __tablename__ = "config"
    id = Column(Integer, primary_key=True)
    interval_seconds = Column(Integer, default=300)
    api_url = Column(
        String,
        default="https://placehold.co/600x400/000000/FFFFFF/png?text=Placeholder",
    )
    dropbox_folder = Column(String, default="/timelapse_images")
    app_id = Column(String)
    app_secret = Column(String)
    dropbox_token = Column(String)
    is_active = Column(Boolean, default=False)
    last_status = Column(String, default="Stopped.")
    last_run_time = Column(DateTime, default=datetime.now(timezone.utc))


class Token(Base):
    """Stores the Dropbox OAuth tokens."""

    __tablename__ = "token"
    id = Column(Integer, primary_key=True)
    access_token = Column(String)
    refresh_token = Column(String)
    expires_at = Column(DateTime)
    user_id = Column(String)  # Dropbox user ID


# Initialize database and ensure the single config row exists
def init_db() -> None:
    """Initialize the database and ensures a single config row is present."""
    Base.metadata.create_all(engine)

    # Use a local session for initialization to keep it separate from the global db_session
    # which is mainly for the background thread.
    init_session = Session()

    # Ensure single Config row
    if not init_session.query(Config).first():
        init_session.add(Config(id=1))
        init_session.commit()
        logger.info("Initialized default configuration.")

    # Ensure single Token row
    if not init_session.query(Token).first():
        init_session.add(Token(id=1))
        init_session.commit()
        logger.info("Initialized token storage.")

    init_session.close()  # Close the temporary initialization session

    global timelapse_thread
    global stop_event

    # Use the global db_session for state restoration (it's persistent for the worker process)
    config = db_session.query(Config).first()
    if config and bool(config.is_active):
        logger.info(
            "Detected active state from previous session. Attempting to restore service.",
        )
        # Start the thread if the app was previously active
        start_timelapse_service()


# --- Dropbox Helper Functions ---


def get_dropbox_session(config: Config, token: Token) -> dropbox.Dropbox:
    """Create and returns a Dropbox instance, refreshing the token if necessary.

    Raises:
        ValueError: If tokens or app credentials are missing.
        dropbox.exceptions.AuthError: If authentication fails.

    """
    if not config.app_id or not config.app_secret:
        msg = "Dropbox App ID and Secret are required."
        raise ValueError(msg)
    if not token.refresh_token:
        msg = "Dropbox Refresh Token is missing. Authorization required."
        raise ValueError(
            msg,
        )

    expires_at_aware = token.expires_at
    if expires_at_aware and expires_at_aware.tzinfo is None:
        expires_at_aware = expires_at_aware.replace(tzinfo=timezone.utc)

    # Get current UTC time, which is always timezone-aware.
    current_utc_time = datetime.now(timezone.utc)

    # Check if access token is expired (or close to expiring, e.g., in the next 5 minutes)
    if (
        expires_at_aware is None
        or expires_at_aware < current_utc_time + timedelta(minutes=5)
    ):
        logger.info(
            "Access token expired or near expiration. Attempting refresh.",
        )

        try:
            dbx_session = dropbox.Dropbox(
                app_key=config.app_id,
                app_secret=config.app_secret,
                oauth2_refresh_token=token.refresh_token,
            )

            # This call triggers the token refresh if needed.
            account = dbx_session.users_get_current_account()
            logger.info(
                f"Token refresh successful. Connected as user: {account.name.display_name}",
            )

            # Return the session object managed by the SDK
            return dbx_session
        except dropbox.exceptions.AuthError:
            logger.exception("Dropbox authentication failed during refresh.")
            raise
        except Exception:
            logger.exception("Failed to establish Dropbox connection.")
            raise

    # If not expired, use the current access token
    return dropbox.Dropbox(
        oauth2_access_token=token.access_token,
        app_key=config.app_id,
        app_secret=config.app_secret,
    )


# --- Background Task Logic ---


def update_status(status_message: str, is_active: bool | None = None):
    """Update the database status and logs the message."""
    local_session = Session()
    try:
        config = local_session.query(Config).first()  # Use the local session
        if config:
            config.last_status = f"{datetime.now(tz=APP_TIMEZONE).strftime('%H:%M:%S')}: {status_message}"
            if is_active is not None:
                config.is_active = is_active
            local_session.commit()  # Commit the local session
    except Exception:
        logger.exception("Failed to update database status.")
        local_session.rollback()  # Rollback the local session
    finally:
        local_session.close()


def timelapse_job():
    """Run main background loop for fetching and uploading images."""
    logger.info("Timelapse background service started.")

    while not stop_event.is_set():
        # Retrieve config and token from the global session for the background job
        config = db_session.query(Config).first()
        token = db_session.query(Token).first()

        try:
            if not config or not token:
                raise Exception("Configuration or Token records are missing.")
            if token:
                db_session.refresh(token)

            interval = config.interval_seconds
            api_url = str(config.api_url)
            dbx_folder = str(config.dropbox_folder)

            update_status(
                f"Attempting image fetch from {api_url}...",
                is_active=True,
            )

            # 1. Get Dropbox Session (handles token refresh)
            dbx = get_dropbox_session(config, token)

            # 2. Fetch Image
            try:
                response = requests.get(api_url, timeout=30)
                response.raise_for_status()

                content_type = response.headers.get("Content-Type", "")
                # Be flexible with image content types
                if "image" not in content_type:
                    raise Exception(
                        f"API returned invalid content type: {content_type}",
                    )

                image_data = response.content
                file_name = f"timelapse_{datetime.now(tz=APP_TIMEZONE).strftime('%Y%m%d_%H%M%S')}.jpg"
                dropbox_path = str(Path(dbx_folder) / file_name).replace(
                    "\\",
                    "/",
                )

            except requests.exceptions.RequestException as e:
                update_status(f"API Connection Error: {e}", is_active=True)
                logger.exception("API Connection Error.")

                # Sleep for 1/10th of interval if an error occurs, to avoid hammering the DB/API
                stop_event.wait(interval / 10 if interval > 10 else 1)
                continue

            # 3. Upload Image to Dropbox
            try:
                # Use WriteMode.add to ensure unique files and avoid conflicts
                dbx.files_upload(
                    f=image_data,
                    path=dropbox_path,
                    mode=dropbox.files.WriteMode.add,
                )

                status_msg = f"SUCCESS: Uploaded '{file_name}' to Dropbox."
                update_status(status_msg, is_active=True)
                logger.info(status_msg)

            except dropbox.exceptions.ApiError as e:
                update_status(f"Dropbox Upload Error: {e}", is_active=True)
                logger.exception("Dropbox Upload Error.")
            except Exception as e:
                update_status(f"Unknown Upload Error: {e}", is_active=True)
                logger.exception("Unknown Upload Error.")

        except Exception as e:
            update_status(
                f"CRITICAL ERROR: {e}. Check configuration.",
                is_active=True,
            )
            logger.critical(f"CRITICAL ERROR in timelapse job: {e}")
            stop_event.wait(5)

        # Wait for the defined interval, checking the stop_event periodically
        stop_event.wait(interval)

    # Final status update when the loop exits
    update_status("Service gracefully stopped.", is_active=False)
    logger.info("Timelapse background service shut down.")


# --- Service Control Functions ---


def start_timelapse_service() -> bool:
    """Start the background service thread."""
    global timelapse_thread
    global stop_event

    with thread_lock:
        if timelapse_thread is None or not timelapse_thread.is_alive():
            stop_event.clear()
            timelapse_thread = threading.Thread(
                target=timelapse_job,
                daemon=True,
            )
            timelapse_thread.start()
            # Update DB state immediately
            update_status("Service starting...", is_active=True)
            logger.info("Timelapse service initiated.")
            return True
        return False


def stop_timelapse_service() -> bool:
    """Stop the background service thread."""
    global timelapse_thread
    global stop_event

    with thread_lock:
        if timelapse_thread is not None and timelapse_thread.is_alive():
            stop_event.set()
            # Wait a short time for the thread to exit cleanly
            timelapse_thread.join(timeout=5)
            timelapse_thread = None
            logger.info("Timelapse service signaled to stop.")
            # Final status update handled by the thread itself
            return True
        return False


# --- Flask Routes ---


@app.before_request
def setup_db_session() -> None:
    """Provide a fresh database session for each request."""
    # Create a new Session instance for the request
    request.db_session = Session()


@app.teardown_request
def shutdown_db_session(exception=None) -> None:
    """Close the database session after each request."""
    if hasattr(request, "db_session") and request.db_session:
        # The correct method to dispose of a Session instance is .close()
        try:
            request.db_session.close()
        except Exception:
            logger.exception("Error closing request DB session.")


@app.route("/")
def index():
    """Load the main configuration and status page."""
    # Use the request-local session for read-only actions
    config = request.db_session.query(Config).first()
    token = request.db_session.query(Token).first()

    # Check if we need to redirect for OAuth Authorization
    if request.args.get("code"):
        return redirect(
            url_for(
                "config_save",
                code=request.args.get("code"),
                state=request.args.get("state"),
            ),
        )

    return render_template("index.html", config=config, token=token)


@app.route("/dropbox_callback", methods=["POST"])
def dropbox_callback() -> tuple[Response, int] | Response:
    """Generate the Dropbox authorization URL using DropboxOAuth2Flow."""
    config = request.db_session.query(Config).first()

    if not config or not config.app_id or not config.app_secret:
        return jsonify(
            {
                "success": False,
                "message": "App ID and Secret must be configured first.",
            },
        ), 400

    try:
        flow = dropbox.DropboxOAuth2Flow(
            consumer_key=config.app_id,
            consumer_secret=config.app_secret,
            redirect_uri=url_for(
                "config_save",
                _external=True,
                _scheme="https",
            ),
            session=session,
            csrf_token_session_key=CSRF_TOKEN_SESSION_KEY,
            token_access_type="offline",  # noqa: S106
        )

        # This will store the flow state in the Flask session and return the auth URL
        auth_url = flow.start()

        return jsonify({"success": True, "auth_url": auth_url})

    except Exception as e:
        logger.exception("Error starting OAuth flow.")
        return jsonify(
            {
                "success": False,
                "message": f"Error starting authorization: {e!s}",
            },
        ), 500


@app.route("/config", methods=["GET", "POST"])
def config_save():
    """Save configuration or exchanges the OAuth code if provided."""
    # Use the request-local session
    session_db = (
        request.db_session
    )  # Use 'session_db' to avoid conflict with 'flask.session'

    # 1. Handle OAuth Code Exchange
    code = request.args.get("code")

    if code:
        # Configuration must already be present to get app credentials
        config = session_db.query(Config).first()
        redirect_uri = request.host_url  # The URL the user was redirected to

        # --- CHANGE: Finish the flow using the data saved in flask.session ---
        try:
            flow = dropbox.DropboxOAuth2Flow(
                consumer_key=config.app_id,
                consumer_secret=config.app_secret,
                redirect_uri=url_for(
                    "config_save",
                    _external=True,
                    _scheme="https",
                ),
                session=session,
                csrf_token_session_key=CSRF_TOKEN_SESSION_KEY,
                token_access_type="offline",  # noqa: S106
            )

            # Finish the flow to exchange the code for tokens
            # This requires passing the entire query dictionary (code and state)
            oauth_result = flow.finish(request.args.to_dict())
            # Save tokens to the database
            token = session_db.query(Token).first()
            token.access_token = oauth_result.access_token
            token.refresh_token = oauth_result.refresh_token
            # Access tokens generally expire after 4 hours (14400 seconds)
            token.expires_at = oauth_result.expires_at
            token.user_id = oauth_result.user_id

            session_db.commit()

            logger.info(
                "Successfully exchanged authorization code and saved tokens.",
            )
            # Force global db_session update
            db_session.expire_all()
            update_status(
                "New Dropbox token successfully saved. Service stopped.",
            )
            # Redirect to clean the URL query string
            return redirect(url_for("index"))

        except dropbox.exceptions.AuthError as e:
            logger.exception(
                "Dropbox authorization error during exchange.",
            )
            update_status(f"Dropbox authorization failed: {e!s}")
            return redirect(url_for("index"))
        except Exception as e:
            session_db.rollback()
            logger.exception("General error during OAuth exchange.")
            update_status(f"OAuth Code exchange failed: {e!s}")
            return redirect(url_for("index"))

    # 2. Handle standard Configuration Save
    if is_service_active():
        return jsonify(
            {
                "success": False,
                "message": "Cannot change config while service is running.",
            },
        ), 400

    try:
        data = request.get_json()
        config = session_db.query(Config).first()

        # Check if App ID or Secret changed
        app_id_changed = config.app_id != data.get("app_id")
        app_secret_changed = config.app_secret != data.get("app_secret")

        # Update config fields
        config.interval_seconds = int(data.get("interval_seconds"))
        config.api_url = data.get("api_url")
        config.dropbox_folder = data.get("dropbox_folder")
        config.app_id = data.get("app_id")
        config.app_secret = data.get("app_secret")

        # Clear tokens if credentials changed (forcing re-auth)
        if app_id_changed or app_secret_changed:
            token = session_db.query(Token).first()
            if token:
                token.access_token = None
                token.refresh_token = None
                token.expires_at = None
                token.user_id = None
            session_db.commit()
            session_db.close()
            # Force global db_session update
            db_session.expire_all()
            update_status(
                "Configuration saved successfully. Tokens cleared, authorization required.",
            )
            return jsonify(
                {
                    "success": True,
                    "message": "Configuration saved. Please re-authorize Dropbox.",
                },
            )

        session_db.commit()
        session_db.close()
        # Force global db_session update
        db_session.expire_all()
        update_status("Configuration saved successfully.")
        return jsonify({"success": True, "message": "Configuration saved."})

    except Exception as e:
        session_db.rollback()
        logger.exception("Failed to save configuration.")
        return jsonify(
            {"success": False, "message": f"Error saving config: {e!s}"},
        ), 500


@app.route("/config_delete", methods=["POST"])
def config_delete() -> tuple[Response, int] | Response:
    """Delete configuration and stops the service."""
    session = request.db_session

    if is_service_active():
        return jsonify(
            {
                "success": False,
                "message": "Cannot delete config while service is running.",
            },
        ), 400

    try:
        # Delete Config and Token data, but keep the tables
        session.query(Config).delete()
        session.query(Token).delete()
        session.commit()

        # Re-initialize default rows
        init_session = Session()
        init_session.add(Config(id=1))
        init_session.add(Token(id=1))
        init_session.commit()
        init_session.close()

        # Force global db_session update
        db_session.expire_all()

        update_status("Configuration and tokens deleted. Reset to default.")
        return jsonify(
            {"success": True, "message": "Configuration deleted and reset."},
        )
    except Exception as e:
        session.rollback()
        logger.exception("Failed to delete configuration.")
        return jsonify(
            {"success": False, "message": f"Error deleting config: {e!s}"},
        ), 500


@app.route("/start", methods=["POST"])
def start_service() -> tuple[Response, int] | Response:
    """Start the timelapse service."""
    config = request.db_session.query(Config).first()
    token = request.db_session.query(Token).first()

    if not config.app_id or not token.refresh_token:
        return jsonify(
            {
                "success": False,
                "message": "Missing Dropbox credentials or token. Please configure and authorize first.",
            },
        ), 400

    if start_timelapse_service():
        return jsonify(
            {"success": True, "message": "Timelapse service starting."},
        )
    return jsonify(
        {"success": False, "message": "Service is already running."},
    ), 409


@app.route("/stop", methods=["POST"])
def stop_service() -> tuple[Response, int] | Response:
    """Stop the timelapse service."""
    if stop_timelapse_service():
        return jsonify(
            {"success": True, "message": "Timelapse service stopping."},
        )
    return jsonify(
        {"success": False, "message": "Service is already stopped."},
    ), 409


def is_service_active() -> bool:
    """Check if the service thread is actively running."""
    global timelapse_thread
    return timelapse_thread is not None and timelapse_thread.is_alive()


@app.route("/status", methods=["GET"])
def get_status() -> Response:
    """Return the current application status and configuration."""
    # Use request-local session
    config = request.db_session.query(Config).first()
    token = request.db_session.query(Token).first()

    is_running = is_service_active()

    # Determine the status based on DB and thread state
    display_status = config.last_status if config else "Configuration Missing."

    if is_running and config and not config.is_active:
        # Edge case: thread is running, but DB flag is wrong. Correct it.
        update_status("Service running (DB state corrected).", is_active=True)

    elif not is_running and config and config.is_active:
        # Edge case: DB flag is active, but thread died. Correct it.
        update_status(
            "Service crashed or manually stopped (DB state corrected).",
            is_active=False,
        )

    # Determine status color/code
    status_code = "warning"
    if is_running:
        status_code = "primary"
        if "ERROR" in display_status or "CRITICAL" in display_status:
            status_code = "danger"
        elif "SUCCESS" in display_status:
            status_code = "success"
    elif (
        "stopped" in display_status.lower()
        or "saved" in display_status.lower()
        or "default" in display_status.lower()
    ):
        status_code = "secondary"

    if (
        not is_running and "CRITICAL" in display_status
    ) or "ERROR" in display_status:
        status_code = "danger"

    # Check for authentication completeness
    is_authenticated = bool(token and token.refresh_token)

    return jsonify(
        {
            "is_running": is_running,
            "is_authenticated": is_authenticated,
            "config": {
                "interval_seconds": config.interval_seconds if config else 300,
                "api_url": config.api_url if config else "",
                "dropbox_folder": config.dropbox_folder if config else "",
                "app_id": config.app_id if config else "",
                "app_secret": config.app_secret if config else "",
            },
            "status": display_status,
            "status_code": status_code,
            "user_id": token.user_id if token else "N/A",
        },
    )


init_db()
