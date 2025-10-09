# Dropbox Timelapse Service

A Python Flask web application that periodically captures images from a specified API endpoint and uploads them to a Dropbox folder. It features robust Dropbox OAuth2 with refresh token handling, per-configuration app credentials, and automatic retries for background uploads.

## Features

* **Web-based Configuration**: Easily configure settings like image capture interval, API endpoint, and Dropbox folder directly from a user-friendly web interface.
* **Dropbox Integration**:
  * **OAuth2 with Refresh Tokens**: Securely authorizes with Dropbox and automatically refreshes access tokens without requiring re-authorization.
  * **Per-Config App Credentials**: Allows you to specify your own Dropbox App ID and Secret, ensuring isolation and control over your application's Dropbox access.
  * **Automatic Retries**: Background upload service handles network issues or temporary Dropbox API errors by retrying failed uploads.
* **Background Service**: Runs the image capture and upload process in a dedicated background thread, ensuring the web UI remains responsive.
* **Docker Support**: Includes a `Dockerfile` for easy containerization and deployment.
* **Status Monitoring**: Provides real-time status updates on the web interface, including service running state, last activity, and authorization status.
* **Timezone Awareness**: Configurable via the `TZ` environment variable.

## Technologies Used

* **Flask**: Web framework for the application.
* **SQLAlchemy**: ORM for SQLite database interaction (to store configuration and tokens).
* **Requests**: For making HTTP requests to the image API.
* **Dropbox SDK**: Official Python SDK for Dropbox API interactions.
* **Gunicorn**: Production-ready WSGI HTTP Server.
* **Bootstrap 5 & Tailwind CSS**: For responsive and modern UI design.

## Getting Started

### Prerequisites

* Python 3.8+
* `pip` (Python package installer)
* Docker (Optional, for containerized deployment)

### 1. Dropbox App Setup

Before running the application, you need to create a Dropbox API app:

1. Go to the [Dropbox Developers App Console](https://www.dropbox.com/developers/apps).
2. Click "Create app".
3. Choose "Scoped access".
4. Choose "Full Dropbox" access type (or "App folder" if you prefer, but remember to adjust the `dropbox_folder` path accordingly).
5. Give your app a unique name.
6. **Permissions**:
    * Ensure your app has at least `files.content.write` and `users.info.read` permissions.
    * Click "Submit".
7. On your app's settings page:
    * Note down your **App key** (Client ID) and **App secret** (Client secret). You'll enter these in the web UI.
    * Under "Redirect URIs", add the full URL of your application's `/config` endpoint. For example, if your app runs locally on port 8080, it would be `http://localhost:8080/config`. If deploying to a specific domain, use that domain (e.g., `https://your-domain.com/config`).

### 2. Local Development Setup (without Docker)

1. **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/dropbox-timelapse-service.git
    cd dropbox-timelapse-service
    ```

2. **Create a virtual environment and install dependencies:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3. **Set Environment Variables:**
    * `FLASK_SECRET_KEY`: **CRITICAL!** Set a strong, random string for Flask session security.
    * `TZ` (Optional): Set your desired timezone (e.g., `America/New_York`, `Europe/London`). If not set, UTC will be used.

    ```bash
    export FLASK_SECRET_KEY="your_super_secret_key_here"
    export TZ="America/New_York" # Example
    ```

4. **Run the application:**

    ```bash
    gunicorn -w 1 -b 0.0.0.0:8080 --log-level info --access-logfile - --error-logfile - timelapse_app:app
    ```

    Alternatively, for simple development:

    ```bash
    export FLASK_APP=timelapse_app.py
    flask run -h 0.0.0.0 -p 8080
    ```

5. Open your web browser and navigate to `http://localhost:8080`.

### 3. Docker Deployment

1. **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/dropbox-timelapse-service.git
    cd dropbox-timelapse-service
    ```

2. **Build the Docker image:**

    ```bash
    docker build -t dropbox-timelapse-app .
    ```

3. **Run the Docker container:**
    * Remember to map port 8080 and mount a volume for the `timelapse.db` file to persist configuration across container restarts.
    * Provide the `FLASK_SECRET_KEY` environment variable.
    * Optionally, provide the `TZ` environment variable.

    ```bash
    docker run -d \
      --name timelapse-service \
      -p 8080:8080 \
      -v "$(pwd)/data:/app/data" \
      -e FLASK_SECRET_KEY="your_super_secret_key_here" \
      -e TZ="America/New_York" \
      dropbox-timelapse-app
    ```

    * The `$(pwd)/data` volume mount will store `timelapse.db` in a `data` folder in your current directory. Make sure this folder exists or Docker will create it.
4. Open your web browser and navigate to `http://localhost:8080`.

## Configuration and Usage

1. **Access the Web UI**: Once the application is running, go to `http://localhost:8080` in your web browser.

2. **Configuration Settings**:
    * **Interval (seconds)**: How often the service fetches an image (e.g., `300` for 5 minutes). Minimum 5 seconds.
    * **Image API URL**: The URL from which the service will fetch images. This endpoint should return a JPEG (or other common image format) when requested. A placeholder like `https://placehold.co/600x400/000000/FFFFFF/png?text=Placeholder` can be used for testing.
    * **Dropbox Folder Path**: The path within your Dropbox where images will be uploaded (e.g., `/My Projects/Timelapse`).
    * **Dropbox OAuth Application ID (Client ID)**: Your Dropbox App key from the Dropbox Developers Console.
    * **Dropbox OAuth Application Secret (Client Secret)**: Your Dropbox App secret from the Dropbox Developers Console.

3. **Save Configuration**:
    * Enter all the required configuration details.
    * Click "Save Configuration".
    * **Important**: You must save the App ID and Secret *before* attempting to authorize for the first time.

4. **Authorize Dropbox Access**:
    * After saving your configuration, click "Authorize Dropbox Access".
    * This will redirect you to Dropbox for authorization. Grant the necessary permissions to your app.
    * Dropbox will then redirect you back to the application, and your tokens will be stored. The UI will update to show "AUTHORIZED".

5. **Service Controls**:
    * **Start Timelapse**: Begins the background process of fetching and uploading images at your specified interval.
    * **Stop Timelapse**: Halts the background service.

6. **Delete Configuration**:
    * You can delete all saved configuration and tokens by clicking "Delete Configuration". This will stop the service if it's running and reset the app to its default state, requiring re-entry of all settings and re-authorization.

## Environment Variables

* **`FLASK_SECRET_KEY`**: (Required) A strong, random string used by Flask to sign session cookies. **Never expose this publicly and ensure it's kept secret in production.**
* **`TZ`**: (Optional) Specifies the timezone for timestamping uploaded files and status messages. Examples: `America/New_York`, `Europe/London`, `Asia/Tokyo`. If not set, UTC is used.

## Database

The application uses an SQLite database named `timelapse.db` to store its configuration and Dropbox tokens. When deploying with Docker, ensure you mount a volume for the `/app/data` directory (or specifically the `timelapse.db` file) to persist this data.

## Contributing

Feel free to open issues or submit pull requests if you have suggestions or improvements.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details. (Note: A `LICENSE` file is not provided, but it's good practice to mention it if you plan to add one).
