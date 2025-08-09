import pytest
import subprocess
import time
import requests
import os
import sys

# Add the directory containing api.py to the Python path
# This helps ensure api.py is discoverable if conftest.py is in a subfolder
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session")
def api_server_url():
    """Provides the URL of the API server."""
    return "http://127.0.0.1:5001"  # Ensure this matches the port in api.py


@pytest.fixture(scope="session")
def api_process(api_server_url):
    """
    Starts the Flask API server as a separate process for the test session
    and yields control back to the tests. Stops the server after tests.
    """
    print("\nStarting API server...")
    # Use sys.executable to ensure the correct python interpreter is used
    # This also ensures Flask is in the path
    process = subprocess.Popen(
        [sys.executable, "-m", "flask", "run", "--port", "5001", "--no-debugger", "--no-reload"],
        env={"FLASK_APP": "api.py", **os.environ},  # Set FLASK_APP env var
        stdout=subprocess.PIPE,  # Capture stdout for potential debugging
        stderr=subprocess.PIPE,  # Capture stderr
    )
    time.sleep(2)  # Give the server a moment to start up

    # Check if the server is actually running
    try:
        requests.get(f"{api_server_url}/data")
        print("API server started successfully.")
    except requests.exceptions.ConnectionError:
        print("API server failed to start.")
        process.terminate()
        process.wait()
        raise Exception("API server did not start. Check api.py and port 5001.")

    yield process  # Yield control to the tests

    # Teardown: Stop the server after all tests in the session are done
    print("Stopping API server...")
    process.terminate()  # or process.kill() for a more forceful stop
    process.wait(timeout=5)  # Wait for the process to terminate
    if process.poll() is None:  # If still running
        print("API server did not terminate gracefully, forcing kill.")
        process.kill()
        process.wait()
    print("API server stopped.")


@pytest.fixture(scope="function")
def api_client(api_server_url, api_process):
    """
    Provides a requests session configured to interact with the running API.
    `api_process` is included to ensure the server is running before tests use the client.
    """
    session = requests.Session()
    # You might want to set a base URL or headers here if your API needs them
    # For now, we'll just use the full URL in tests.
    yield session
    session.close()
