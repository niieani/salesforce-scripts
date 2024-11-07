import requests
import time
import sys
import logging
import zipfile
import io
import os
import base64
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
from getpass import getpass

# Setup logging
logger = logging.getLogger("salesforce_flow_search")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def authenticate(config: dict) -> tuple:
    auth_params = {
        "grant_type": "password",
        "client_id": config["client_id"],
        "client_secret": config["client_secret"],
        "username": config["username"],
        "password": f"{config['password']}{config['security_token']}",
    }

    try:
        response = requests.post(
            f"{config['instance_url']}/services/oauth2/token", data=auth_params
        )
        response.raise_for_status()
        auth_data = response.json()
        logger.info("Successfully authenticated with Salesforce")
        return auth_data["access_token"], auth_data["instance_url"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication failed: {str(e)}")
        raise


def retrieve_flows(access_token: str, instance_url: str) -> str:
    headers = {"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": "retrieve"}

    # Initial retrieve request
    package_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
            <env:Header>
                <ns1:SessionHeader xmlns:ns1="http://soap.sforce.com/2006/04/metadata">
                    <ns1:sessionId>{}</ns1:sessionId>
                </ns1:SessionHeader>
            </env:Header>
            <env:Body>
                <ns1:retrieve xmlns:ns1="http://soap.sforce.com/2006/04/metadata">
                    <ns1:retrieveRequest>
                        <ns1:apiVersion>57.0</ns1:apiVersion>
                        <ns1:unpackaged>
                            <types>
                                <members>*</members>
                                <name>Flow</name>
                            </types>
                            <version>57.0</version>
                        </ns1:unpackaged>
                    </ns1:retrieveRequest>
                </ns1:retrieve>
            </env:Body>
        </env:Envelope>""".format(
        access_token
    )

    url = f"{instance_url}/services/Soap/m/57.0"

    try:
        response = requests.post(url, headers=headers, data=package_xml)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        retrieve_request_id = root.find(
            ".//{http://soap.sforce.com/2006/04/metadata}id"
        ).text
        logger.info(f"Retrieve request ID: {retrieve_request_id}")
    except (requests.exceptions.RequestException, AttributeError) as e:
        logger.error(f"Error initiating retrieve request: {str(e)}")
        raise

    # Poll for completion
    poll_body_template = """<?xml version="1.0" encoding="UTF-8"?>
        <env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
            <env:Header>
                <ns1:SessionHeader xmlns:ns1="http://soap.sforce.com/2006/04/metadata">
                    <ns1:sessionId>{}</ns1:sessionId>
                </ns1:SessionHeader>
            </env:Header>
            <env:Body>
                <ns1:checkRetrieveStatus xmlns:ns1="http://soap.sforce.com/2006/04/metadata">
                    <ns1:asyncProcessId>{}</ns1:asyncProcessId>
                </ns1:checkRetrieveStatus>
            </env:Body>
        </env:Envelope>"""

    namespaces = {
        "soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
        "met": "http://soap.sforce.com/2006/04/metadata",
    }

    while True:
        poll_body = poll_body_template.format(access_token, retrieve_request_id)
        poll_response = requests.post(url, headers=headers, data=poll_body)
        poll_root = ET.fromstring(poll_response.content)

        if poll_root.find(".//met:done", namespaces).text.lower() == "true":
            if poll_root.find(".//met:status", namespaces).text == "Succeeded":
                zip_data = poll_root.find(".//met:zipFile", namespaces).text
                zip_data_bytes = io.BytesIO(base64.b64decode(zip_data))

                extract_path = "flows_metadata"
                with zipfile.ZipFile(zip_data_bytes, "r") as zip_ref:
                    zip_ref.extractall(extract_path)
                logger.info("Retrieved and extracted Flow metadata")
                return extract_path
            else:
                raise ValueError("Retrieve request failed")
        time.sleep(2)


def search_flows(extract_path: str, search_string: str) -> None:
    matching_flows = []

    for root, _, files in os.walk(extract_path):
        for file in files:
            if file.endswith(".flow"):
                flow_path = os.path.join(root, file)
                try:
                    tree = ET.parse(flow_path)
                    flow_root = tree.getroot()
                    flow_content = ET.tostring(flow_root, encoding="unicode")

                    if search_string.lower() in flow_content.lower():
                        label_elem = flow_root.find(
                            ".//{http://soap.sforce.com/2006/04/metadata}label"
                        )
                        matching_flows.append(
                            label_elem.text
                            if label_elem is not None
                            else os.path.splitext(file)[0]
                        )
                except ET.ParseError as e:
                    logger.warning(f"Could not parse flow file {file}: {str(e)}")

    if matching_flows:
        logger.info(
            f"\nFound {len(matching_flows)} flows containing '{search_string}':"
        )
        for flow in matching_flows:
            print(f"Flow Name: {flow}")
    else:
        logger.info(f"\nNo flows found containing '{search_string}'")


def load_config() -> dict:
    load_dotenv()

    config = {
        "client_id": os.getenv("SALESFORCE_CLIENT_ID"),
        "client_secret": os.getenv("SALESFORCE_CLIENT_SECRET"),
        "username": os.getenv("SALESFORCE_USERNAME"),
        "instance_url": os.getenv("SALESFORCE_INSTANCE_URL"),
        "password": os.getenv("SALESFORCE_PASSWORD"),
        "security_token": os.getenv("SALESFORCE_SECURITY_TOKEN"),
    }

    required = ["client_id", "client_secret", "username", "instance_url"]
    missing = [field for field in required if not config[field]]
    if missing:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing)}"
        )

    if not config["password"]:
        config["password"] = getpass("Enter your Salesforce password: ")
    if not config["security_token"]:
        config["security_token"] = getpass("Enter your Salesforce security token: ")

    return config


def main():
    if len(sys.argv) != 2:
        print("Usage: python flows.py <search_string>")
        sys.exit(1)

    try:
        config = load_config()
        access_token, instance_url = authenticate(config)
        extract_path = retrieve_flows(access_token, instance_url)
        search_flows(extract_path, sys.argv[1])
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
