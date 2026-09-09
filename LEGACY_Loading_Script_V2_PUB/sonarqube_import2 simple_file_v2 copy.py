import requests
from requests.auth import HTTPBasicAuth
import json
import os
import time
import difflib
import configparser
from pathlib import Path


def _read_phoenix_config(config_file='config.ini'):
    """
    Read config.ini from next to this script, if it exists.

    :param config_file: Config file name, resolved next to this script
    :return: ConfigParser instance, or None when the file is absent
    """
    config_path = Path(__file__).parent / config_file
    if not config_path.exists():
        return None

    config = configparser.ConfigParser()
    config.read(config_path)
    return config


def load_phoenix_credentials(config_file='config.ini'):
    """
    Load Phoenix API credentials.

    Environment variables PHOENIX_CLIENT_ID / PHOENIX_CLIENT_SECRET take
    precedence over config.ini and are sufficient on their own: the config file
    is only read when a credential is missing from the environment. This keeps
    CI runners working without a config.ini on disk.

    :param config_file: Config file name, resolved next to this script
    :return: Tuple of (client_id, client_secret)
    """
    client_id = os.environ.get('PHOENIX_CLIENT_ID')
    client_secret = os.environ.get('PHOENIX_CLIENT_SECRET')

    if not (client_id and client_secret):
        config = _read_phoenix_config(config_file)
        if config is not None:
            client_id = client_id or config.get('phoenix', 'client_id', fallback=None)
            client_secret = client_secret or config.get('phoenix', 'client_secret', fallback=None)

    missing = [name for name, value in
               (('client_id', client_id), ('client_secret', client_secret)) if not value]
    if missing:
        config_path = Path(__file__).parent / config_file
        raise ValueError(
            "Missing Phoenix credential(s): %s. Set PHOENIX_CLIENT_ID / "
            "PHOENIX_CLIENT_SECRET in the environment, or add them to the "
            "[phoenix] section of %s." % (', '.join(missing), config_path))

    return client_id, client_secret


def load_phoenix_api_url(default, config_file='config.ini'):
    """
    Resolve the Phoenix API base URL.

    Precedence: PHOENIX_API_BASE_URL env var, then [phoenix] api_url in
    config.ini, then the supplied default.

    :param default: Fallback URL when neither env var nor config supplies one
    :param config_file: Config file name, resolved next to this script
    :return: Phoenix API base URL, without a trailing slash
    """
    env_url = os.environ.get('PHOENIX_API_BASE_URL')
    if env_url:
        return env_url.rstrip('/')

    config = _read_phoenix_config(config_file)
    from_config = config.get('phoenix', 'api_url', fallback=None) if config is not None else None
    return (from_config or default).rstrip('/')


# Configuration parameters
# Credentials come from config.ini ([phoenix] client_id / client_secret)
CLIENT_ID, CLIENT_SECRET = load_phoenix_credentials()
#API_BASE_URL = "https://api.demo.appsecphx.io"
API_BASE_URL = "https://api.poc1.appsecphx.io"

# Honour [phoenix] api_url / PHOENIX_API_BASE_URL when supplied; the literal
# above stays the default so existing behaviour is unchanged.
API_BASE_URL = load_phoenix_api_url(API_BASE_URL)

# Import parameters
FILE_PATH = 'scanner-sample/owasp-benchmarkjava.json'
SCAN_TYPE = 'SonarQube Scan'
ASSESSMENT_NAME = 'OWASP Benchmark_EXAMPLE'
IMPORT_TYPE = 'new'
SCAN_TARGET = 'owasp.benchmark.example.com'
AUTO_IMPORT = True
WAIT_FOR_COMPLETION = True

# Scanner types file path
SCANNER_TYPES_FILE = 'Utilis/Loading Script/Sanner_Selection.txt'

def load_scanner_types(file_path=SCANNER_TYPES_FILE):
    """
    Load valid scanner types from the specified file.
    
    :param file_path: Path to the file containing valid scanner types
    :return: List of valid scanner types
    """
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Warning: Scanner types file '{file_path}' not found.")
        return []

def find_closest_scanner_type(scanner_type, valid_scanner_types):
    """
    Find the closest matching scanner type from the list of valid types.
    
    :param scanner_type: The scanner type to validate
    :param valid_scanner_types: List of valid scanner types
    :return: The closest matching scanner type or None if no close match
    """
    if not valid_scanner_types:
        return None
    
    matches = difflib.get_close_matches(scanner_type, valid_scanner_types, n=1, cutoff=0.6)
    return matches[0] if matches else None

def validate_scanner_type(scanner_type):
    """
    Validate if the provided scanner type is in the list of valid types.
    If not, suggest the closest match.
    
    :param scanner_type: The scanner type to validate
    :return: The validated scanner type (either the original or the closest match)
    """
    valid_scanner_types = load_scanner_types()
    
    if scanner_type in valid_scanner_types:
        return scanner_type
    
    closest_match = find_closest_scanner_type(scanner_type, valid_scanner_types)
    if closest_match:
        print(f"Warning: '{scanner_type}' is not a valid scanner type.")
        print(f"Did you mean '{closest_match}'?")
        return closest_match
    else:
        print(f"Warning: '{scanner_type}' is not a valid scanner type.")
        print("Using the provided scanner type anyway.")
        return scanner_type

def get_access_token(client_id, client_secret):
    # The line `url = "https://api.https://demo2.appsecphx.io//v1/auth/access_token"` is defining the URL
    # endpoint for obtaining an access token. This URL is used in the `get_access_token` function to make
    # a GET request with HTTP basic authentication using the provided client ID and client secret. The
    # response from this URL is expected to contain the access token needed for authentication in
    # subsequent API requests.
    url = f"{API_BASE_URL}/v1/auth/access_token"

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(response.status_code)
        print("Failed to obtain token:", response.text)
    return None

def check_import_status(request_id, client_id, client_secret):
    """
    Check the status of an import request.
    
    :param request_id: The UUID identifying the import request
    :param client_id: Client ID for authentication
    :param client_secret: Client secret for authentication
    :return: The status response from the API
    """
    token = get_access_token(client_id, client_secret)
    if token is None:
        return None
    
    url = f"{API_BASE_URL}/v1/import/assets/file/translate/request/{request_id}"
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Status Code: {response.status_code}")
        print(f"Failed to check import status: {response.text}")
        return None

def wait_for_import_completion(request_id, client_id, client_secret, check_interval=10, timeout=3600):
    """
    Continuously check the status of an import until it completes or times out.
    
    :param request_id: The UUID identifying the import request
    :param client_id: Client ID for authentication
    :param client_secret: Client secret for authentication
    :param check_interval: Time in seconds between status checks (default: 10)
    :param timeout: Maximum time in seconds to wait for completion (default: 3600 = 1 hour)
    :return: The final status response from the API
    """
    start_time = time.time()
    
    while True:
        status_response = check_import_status(request_id, client_id, client_secret)
        
        if status_response is None:
            print("Failed to get status response")
            return None
        
        current_status = status_response.get('status')
        print(f"Current import status: {current_status}")
        
        if current_status == "IMPORTED":
            print("Import completed successfully!")
            return status_response
        elif current_status == "ERROR":
            print(f"Import failed with error: {status_response.get('error', 'Unknown error')}")
            return status_response
        elif current_status in ["TRANSLATING", "READY_FOR_IMPORT"]:
            # Check if we've exceeded the timeout
            if time.time() - start_time > timeout:
                print(f"Import timed out after {timeout} seconds")
                return status_response
            
            # Wait before checking again
            print(f"Waiting {check_interval} seconds before checking again...")
            time.sleep(check_interval)
        else:
            print(f"Unknown status: {current_status}")
            return status_response

def send_results(file_path, scan_type, assessment_name, import_type, client_id, client_secret, scan_target=None, auto_import=True, wait_for_completion=True):
    """
    Send scan results to the API and optionally wait for the import to complete.
    
    :param file_path: Path to the file to be imported
    :param scan_type: Type of scan (e.g., "SonarQube Scan")
    :param assessment_name: Name of the assessment
    :param import_type: Type of import ("new" or "merge")
    :param client_id: Client ID for authentication
    :param client_secret: Client secret for authentication
    :param scan_target: Target of the scan (optional)
    :param auto_import: Whether to automatically import after processing (default: True)
    :param wait_for_completion: Whether to wait for the import to complete (default: True)
    :return: The import request ID and final status response if wait_for_completion is True
    """
    # Validate scanner type
    scan_type = validate_scanner_type(scan_type)
    
    token = get_access_token(client_id, client_secret)
    if token is None:
        return None, None
    
    url = f"{API_BASE_URL}/v1/import/assets/file/translate"

    headers = {
        'Authorization': f'Bearer {token}'
    }
    files = {
        'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')
    }
    data = {
        'scanType': scan_type,
        'assessmentName': assessment_name,
        'importType': import_type,
        'scanTarget': scan_target if scan_target else '',
        'autoImport': 'true' if auto_import else 'false'
    }
    
    response = requests.post(url, headers=headers, files=files, data=data)
    files['file'][1].close() # Make sure to close the file
    
    print("Status Code:", response.status_code)
    
    if response.status_code != 200:
        print("Failed to send results:", response.text)
        return None, None
    
    response_data = response.json()
    print("Response:", response_data)
    
    request_id = response_data.get('id')
    
    if wait_for_completion and request_id:
        print(f"Waiting for import to complete (request ID: {request_id})...")
        final_status = wait_for_import_completion(request_id, client_id, client_secret)
        return request_id, final_status
    
    return request_id, response_data

# Example usage
#client_id = os.environ["CLIENT_ID"]
#client_secret = os.environ["CLIENT_SECRET"]

#client_id = "YOUR_CLIENT_ID"
#client_secret = "YOUR_CLIENT_SECRET"

# Use the parameters defined at the top of the file
request_id, final_status = send_results(
    FILE_PATH, 
    SCAN_TYPE, 
    ASSESSMENT_NAME, 
    IMPORT_TYPE, 
    CLIENT_ID, 
    CLIENT_SECRET, 
    SCAN_TARGET,
    AUTO_IMPORT,
    WAIT_FOR_COMPLETION
)

# Example without waiting for completion
# request_id, response = send_results(
#     FILE_PATH, 
#     SCAN_TYPE, 
#     ASSESSMENT_NAME, 
#     IMPORT_TYPE, 
#     CLIENT_ID, 
#     CLIENT_SECRET, 
#     SCAN_TARGET,
#     AUTO_IMPORT,
#     False
# )
# 
# # Check status manually later
# if request_id:
#     status = check_import_status(request_id, CLIENT_ID, CLIENT_SECRET)
#     print(f"Current status: {status.get('status')}")