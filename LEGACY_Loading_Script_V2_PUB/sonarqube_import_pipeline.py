#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import argparse
import sys
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

def get_access_token(client_id, client_secret, phoenix_url):
    """Get an access token from Phoenix."""
    url = f"{phoenix_url}/v1/auth/access_token"
    
    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(f"Status code: {response.status_code}")
        print(f"Failed to obtain token: {response.text}")
        return None

def send_results(file_path, scan_type, assessment_name, import_type, client_id, client_secret, 
                scan_target=None, auto_import=True, phoenix_url="https://api.poc1.appsecphx.io"):
    """Send scan results to Phoenix."""
    token = get_access_token(client_id, client_secret, phoenix_url)
    if token is None:
        return False
    
    url = f"{phoenix_url}/v1/import/assets/file/translate"
    
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    try:
        with open(file_path, 'rb') as f:
            files = {
                'file': (os.path.basename(file_path), f, 'application/json')
            }
            
            data = {
                'scanType': scan_type,
                'assessmentName': assessment_name,
                'importType': import_type,
                'scanTarget': scan_target if scan_target else '',
                'autoImport': 'true' if auto_import else 'false'
            }
            
            response = requests.post(url, headers=headers, files=files, data=data)
            
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            return response.status_code == 200
    except Exception as e:
        print(f"Error sending results: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Send SonarQube results to Phoenix')
    parser.add_argument('--file', required=True, help='Path to the SonarQube JSON report file')
    parser.add_argument('--scan-type', default='sonarqube', help='Type of scan')
    parser.add_argument('--assessment-name', required=True, help='Name of the assessment')
    parser.add_argument('--import-type', default='new', help='Import type')
    parser.add_argument('--client-id', help='Phoenix client ID (defaults to config.ini)')
    parser.add_argument('--client-secret', help='Phoenix client secret (defaults to config.ini)')
    parser.add_argument('--scan-target', help='Target of the scan')
    parser.add_argument('--auto-import', action='store_true', default=True, help='Auto import assets')
    parser.add_argument('--phoenix-url',
                        help='Phoenix API URL (defaults to PHOENIX_API_BASE_URL, '
                             'then [phoenix] api_url in config.ini)')

    args = parser.parse_args()

    # Resolved after parsing, not as an argparse default: a default is built
    # even when --phoenix-url is given, which would make an explicit URL still
    # depend on a readable config.ini. Normalise the explicit value too, so it
    # gets the same trailing-slash handling as a resolved one and the f-strings
    # below never produce a double slash.
    if args.phoenix_url:
        args.phoenix_url = args.phoenix_url.rstrip('/')
    else:
        args.phoenix_url = load_phoenix_api_url('https://api.poc1.appsecphx.io')

    # CLI args win; anything not passed falls back to config.ini
    # Only fall back to env/config when a credential was not passed on the
    # command line, so pipelines that supply both keep working without a
    # config.ini on disk (config.ini is gitignored, so it is absent on a fresh
    # checkout).
    if args.client_id and args.client_secret:
        client_id, client_secret = args.client_id, args.client_secret
    else:
        config_client_id, config_client_secret = load_phoenix_credentials()
        client_id = args.client_id or config_client_id
        client_secret = args.client_secret or config_client_secret

    success = send_results(
        args.file,
        args.scan_type,
        args.assessment_name,
        args.import_type,
        client_id,
        client_secret,
        args.scan_target,
        args.auto_import,
        args.phoenix_url
    )
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()

