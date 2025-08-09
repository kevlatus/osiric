import pytest


def test_get_data_from_api(api_client, api_server_url):
    """Test retrieving data from the running API."""
    response = api_client.get(f"{api_server_url}/data")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello from API!"}


def test_submit_data_to_api(api_client, api_server_url):
    """Test submitting data to the running API."""
    payload = {"name": "Test User", "value": 123}
    response = api_client.post(f"{api_server_url}/submit", json=payload)
    assert response.status_code == 200
    assert response.json() == {"received": payload, "status": "success"}


def test_another_api_interaction(api_client, api_server_url):
    """Another test that uses the API."""
    response = api_client.get(f"{api_server_url}/nonexistent")  # Test a 404
    assert response.status_code == 404


# A test that *doesn't* require the API
def test_local_logic():
    assert 1 + 1 == 2
