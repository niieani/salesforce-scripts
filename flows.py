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


class SalesforceFlowSearch:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        security_token: str,
        instance_url: str,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.security_token = security_token
        self.auth_url = f"{instance_url}/services/oauth2/token"
        self.access_token = None
        self.instance_url = instance_url
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("salesforce_flow_search")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def authenticate(self) -> None:
        auth_params = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": f"{self.password}{self.security_token}",
        }

        try:
            response = requests.post(self.auth_url, data=auth_params)
            response.raise_for_status()
            auth_data = response.json()

            self.access_token = auth_data["access_token"]
            self.instance_url = auth_data["instance_url"]
            self.logger.info("Successfully authenticated with Salesforce")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Authentication failed: {str(e)}")
            raise

    def retrieve_flows(self) -> str:
        if not self.access_token or not self.instance_url:
            raise ValueError("Not authenticated. Call authenticate() first.")

        headers = {"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": "retrieve"}

        # Full SOAP Envelope for Metadata API Retrieve request
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
            self.access_token
        )

        url = f"{self.instance_url}/services/Soap/m/57.0"

        # Step 1: Send initial retrieve request and capture request ID
        try:
            response = requests.post(url, headers=headers, data=package_xml)
            response.raise_for_status()

            # Parse response to get retrieve request ID
            root = ET.fromstring(response.content)
            retrieve_request_id_element = root.find(
                ".//{http://soap.sforce.com/2006/04/metadata}id"
            )
            if retrieve_request_id_element is None:
                self.logger.error("Retrieve request ID not found in the response.")
                raise ValueError("Retrieve request ID not found in the response.")
            retrieve_request_id = retrieve_request_id_element.text
            self.logger.info(f"Retrieve request ID: {retrieve_request_id}")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error initiating retrieve request: {str(e)}")
            raise

        # Step 2: Poll for retrieve completion
        poll_url = f"{self.instance_url}/services/Soap/m/57.0"
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

        while True:
            poll_body = poll_body_template.format(
                self.access_token, retrieve_request_id
            )
            try:
                poll_response = requests.post(poll_url, headers=headers, data=poll_body)
                poll_response.raise_for_status()

                # Define namespace mapping
                namespaces = {
                    "soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
                    "met": "http://soap.sforce.com/2006/04/metadata",
                }

                poll_root = ET.fromstring(poll_response.content)

                # Find the done element first
                done_element = poll_root.find(".//met:done", namespaces)
                if done_element is not None and done_element.text.lower() == "true":
                    # Check status
                    status_element = poll_root.find(".//met:status", namespaces)
                    if (
                        status_element is not None
                        and status_element.text == "Succeeded"
                    ):
                        zip_data_element = poll_root.find(".//met:zipFile", namespaces)
                        if zip_data_element is not None:
                            zip_data = zip_data_element.text
                            zip_data_bytes = io.BytesIO(base64.b64decode(zip_data))

                            # Save and extract the ZIP content
                            with zipfile.ZipFile(zip_data_bytes, "r") as zip_ref:
                                extract_path = "flows_metadata"
                                zip_ref.extractall(extract_path)
                            self.logger.info(
                                "Retrieve request completed and extracted Flow metadata."
                            )
                            return extract_path
                        else:
                            self.logger.error(
                                "Retrieve request completed but no zipFile found."
                            )
                            raise ValueError(
                                "Retrieve request completed but no zipFile found."
                            )
                    else:
                        self.logger.error("Retrieve request failed.")
                        raise ValueError("Retrieve request failed.")

                # Wait before next poll
                time.sleep(2)

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error polling retrieve status: {str(e)}")
                raise

    def search_flows(self, search_string: str) -> None:
        try:
            extract_path = self.retrieve_flows()
            matching_flows = []

            for root, _, files in os.walk(extract_path):
                for file in files:
                    if file.endswith(".flow"):
                        flow_path = os.path.join(root, file)
                        try:
                            tree = ET.parse(flow_path)
                            flow_root = tree.getroot()

                            # Convert the entire XML to string for searching
                            flow_content = ET.tostring(flow_root, encoding="unicode")

                            if search_string.lower() in flow_content.lower():
                                # Extract the flow label
                                label_elem = flow_root.find(
                                    ".//{http://soap.sforce.com/2006/04/metadata}label"
                                )
                                if label_elem is not None:
                                    matching_flows.append(label_elem.text)
                                else:
                                    # Fallback to filename if label is not found
                                    matching_flows.append(os.path.splitext(file)[0])

                        except ET.ParseError as e:
                            self.logger.warning(
                                f"Could not parse flow file {file}: {str(e)}"
                            )
                            continue

            # Report results
            if matching_flows:
                self.logger.info(
                    f"\nFound {len(matching_flows)} flows containing '{search_string}':"
                )
                for flow in matching_flows:
                    print(f"Flow Name: {flow}")
            else:
                self.logger.info(f"\nNo flows found containing '{search_string}'")

        except Exception as e:
            self.logger.error(f"Error searching flows: {str(e)}")
            raise


def load_config():
    load_dotenv()

    config = {
        "client_id": os.getenv("SALESFORCE_CLIENT_ID"),
        "client_secret": os.getenv("SALESFORCE_CLIENT_SECRET"),
        "username": os.getenv("SALESFORCE_USERNAME"),
        "instance_url": os.getenv("SALESFORCE_INSTANCE_URL"),
        "password": os.getenv("SALESFORCE_PASSWORD"),
        "security_token": os.getenv("SALESFORCE_SECURITY_TOKEN"),
    }

    # Validate required fields
    required_fields = ["client_id", "client_secret", "username", "instance_url"]
    missing_fields = [field for field in required_fields if not config[field]]
    if missing_fields:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing_fields)}"
        )

    # Prompt for password if not in env
    if not config["password"]:
        config["password"] = getpass("Enter your Salesforce password: ")

    # Prompt for security token if not in env
    if not config["security_token"]:
        config["security_token"] = getpass("Enter your Salesforce security token: ")

    return config


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <search_string>")
        sys.exit(1)

    search_string = sys.argv[1]

    # Initialize and run search
    try:
        config = load_config()
        sf_search = SalesforceFlowSearch(**config)
        sf_search.authenticate()
        sf_search.search_flows(search_string)

    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
