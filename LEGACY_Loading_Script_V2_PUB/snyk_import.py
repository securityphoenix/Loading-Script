import requests
from requests.auth import HTTPBasicAuth
import json
import os
import configparser
from pathlib import Path

API_BASE_URL = "https://api.poc1.appsecphx.io"


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

# Honour [phoenix] api_url / PHOENIX_API_BASE_URL when supplied; the literal
# above stays the default so existing behaviour is unchanged.
API_BASE_URL = load_phoenix_api_url(API_BASE_URL)


def get_access_token(client_id, client_secret):
    url = f"{API_BASE_URL}/v1/auth/access_token"
    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(response.status_code)
        print("Failed to obtain token:", response.text)
    return None

def send_results(file_path, scan_type, assessment_name, import_type, client_id,client_secret, scan_target=None, auto_import=True):
    token = get_access_token(client_id, client_secret)
    if token is None:
        return
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
    print("Response:", response.json())

# Example usage
# Credentials come from config.ini ([phoenix] client_id / client_secret)
client_id, client_secret = load_phoenix_credentials()


#send_results('path_to_your_report_file.ext', 'YourScanType', 'YourAssessmentName', 'new', client_id, client_secret, scan_target)
# Aligned for overlap demo: Snyk side of the EXAMPLE pair -> shared asset on poc1
send_results('scanner-sample/snyk_example.json', 'Snyk Scan', 'Overlap-Example-Snyk', 'new', client_id, client_secret, "phx.test/overlap-example-app:latest")
#use com.example.tests/example:latest for the container name
