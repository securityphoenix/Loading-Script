import requests
from requests.auth import HTTPBasicAuth
import json
import os
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

# Previously hardcoded inline at each call site. Honours [phoenix] api_url /
# PHOENIX_API_BASE_URL when supplied; poc1 stays the default.
API_BASE_URL = load_phoenix_api_url("https://api.poc1.appsecphx.io")

def get_access_token(client_id, client_secret):
    """
    Obtain an access token from the Phoenix API using client credentials.
    
    :param client_id: The client ID for API authentication
    :param client_secret: The client secret for API authentication
    :return: Access token string if successful, None otherwise
    """
    #url = "https://api.demo.appsecphx.io/v1/auth/access_token"
    url = f"{API_BASE_URL}/v1/auth/access_token"

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(response.status_code)
        print("Failed to obtain token:", response.text)
    return None

def send_results(file_path, scan_type, assessment_name, import_type, client_id,client_secret, scan_target=None, auto_import=True):
    """
    The function `send_results` sends scan results to a specified API endpoint using a file path and
    other parameters.
    
    :param file_path: The `file_path` parameter in the `send_results` function represents the path to
    the file that you want to send for processing. It should be a string that specifies the location of
    the file on your system. For example, it could be something like "/path/to/your/file.txt"
    :param scan_type: Scan type refers to the type of scan being performed, such as "web application
    scan" or "network scan". It helps identify the purpose or focus of the scan being conducted
    :param assessment_name: Assessment_name is a parameter that represents the name of the assessment
    being conducted or the assessment file being imported. It is a user-defined name that helps identify
    the specific assessment or scan being performed
    :param import_type: The `import_type` parameter in the `send_results` function specifies the type of
    import being performed. It is used to indicate how the file should be imported or processed by the
    API. This parameter helps the API understand the format or method to use when handling the file
    data. It could be values
    :param client_id: Client ID is a unique identifier assigned to a client application when it is
    registered with the API provider. It is used to authenticate the client application when making
    requests to the API
    :param client_secret: It seems like you were about to ask something related to the `client_secret`
    parameter in the `send_results` function. How can I assist you further with this parameter or any
    other aspect of the function?
    :param scan_target: The `scan_target` parameter in the `send_results` function is used to specify
    the target for the scan. It is an optional parameter, so if a value is not provided, it defaults to
    an empty string (''). This parameter allows you to specify the target of the scan, such as a
    :param auto_import: The `auto_import` parameter in the `send_results` function is a boolean
    parameter that specifies whether the imported assets should be automatically imported. If
    `auto_import` is set to `True`, the assets will be automatically imported; if set to `False`, manual
    intervention may be required for importing the, defaults to True (optional)
    :return: The `send_results` function returns nothing explicitly. It either returns `None` if the
    access token is not obtained successfully or it completes the HTTP POST request to the specified URL
    and prints the status code and response JSON.
    """
    token = get_access_token(client_id, client_secret)
    if token is None:
        return
    #url = "https://api.demo.appsecphx.io/v1/import/assets/file/translate"
    url = f"{API_BASE_URL}/v1/import/assets/file/translate"    

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        return
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    # Use context manager to properly handle file opening/closing
    with open(file_path, 'rb') as file:
        files = {
            'file': (os.path.basename(file_path), file, 'application/octet-stream')
        }
        data = {
            'scanType': scan_type,
            'assessmentName': assessment_name,
            'importType': import_type,
            'scanTarget': scan_target if scan_target else '',
            'autoImport': 'true' if auto_import else 'false'
        }
        response = requests.post(url, headers=headers, files=files, data=data)
    
    print("Status Code:", response.status_code)
    print("Response:", response.json())

# Example usage
# Credentials come from config.ini ([phoenix] client_id / client_secret)
client_id, client_secret = load_phoenix_credentials()


#send_results('path_to_your_report_file.ext', 'YourScanType', 'YourAssessmentName', 'new', client_id, client_secret, scan_target)

# Aligned for overlap demo: Aqua side of the EXAMPLE pair -> same shared asset on poc1
send_results('scanner-sample/aqua_example2.json', 'Aqua Scan', 'Overlap-Example-Aqua', 'new', client_id, client_secret, "phx.test/overlap-example-app:latest")
