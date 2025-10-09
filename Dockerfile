# Use a lightweight base image
FROM python:3.14-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir templates data

# Copy the application code
COPY timelapse_app.py .
COPY templates/ ./templates/.

# Expose the port (Flask default)
EXPOSE 8080
VOLUME /app

# Command to run the application (using gunicorn for production stability)
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:8080","--log-level", "info", "--access-logfile", "-", "--error-logfile", "-", "timelapse_app:app"]
