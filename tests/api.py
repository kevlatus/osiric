# api.py
from flask import Flask, jsonify, request
import time

app = Flask(__name__)


@app.route('/data')
def get_data():
    return jsonify({"message": "Hello from API!"})


@app.route('/submit', methods=['POST'])
def submit_data():
    data = request.json
    return jsonify({"received": data, "status": "success"})


# This part is for running the API directly, not usually used when run by pytest
if __name__ == '__main__':
    # In a real scenario, you might have a different way to start/stop the API,
    # but for testing, we often use a specific port and ensure it's free.
    app.run(port=5001, debug=False)  # Use a dedicated port for tests
