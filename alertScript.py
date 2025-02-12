# %pip install requests
# %pip install urllib3

from __future__ import print_function
import rapid7vmconsole
from rapid7vmconsole.rest import ApiException
import urllib3
from xml.etree import ElementTree as ET
import requests
import base64
import time
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess

def setup_rapid7(config_file_path, server_name):
    """
    Reads the configuration from an XML file.
    """
    urllib3.disable_warnings()
    config = rapid7vmconsole.Configuration(name='Rapid7')

    config.verify_ssl = False
    config.assert_hostname = False
    config.proxy = None
    config.ssl_ca_cert = None
    config.connection_pool_maxsize = None
    config.cert_file = None
    config.key_file = None
    config.safe_chars_for_path_param = ''
    config.debug = False

    email_config = {}  # To store email settings

    try:
        # Getting the config parameters from the configuration file
        config_file= ET.parse(config_file_path)
        root=config_file.getroot()

        for server in root.findall('server'):
            if server.get('name') == server_name:
                config.username=server.find('username').text
                config.password=server.find('password').text
                config.host=server.find('host').text
                config.api_key=server.find('api_key').text.strip('{}')
                server_found = True
                break
                
        if not server_found:
            raise ValueError(f"Server '{server_name}' not found in config file")
        

        email_section = root.find('email')
        if email_section is not None:
            email_config['recipient_email'] = email_section.find('recipient_email').text
            email_config['sender_email'] = email_section.find('sender_email').text
            email_config['smtp_server'] = email_section.find('smtp_server').text
            email_config['smtp_port'] = int(email_section.find('smtp_port').text)  # Ensure it's an integer
        

        # Set up authentication
        auth = f"{config.username}:{config.password}"
        auth = base64.b64encode(auth.encode('ascii')).decode()
        
        # Create API client
        api_client = rapid7vmconsole.ApiClient(configuration=config)
        api_client.default_headers['Authorization'] = f"Basic {auth}"
        
        # Create report client
        report_client = rapid7vmconsole.ReportApi(api_client)
        
        print(f"Successfully connected to {server_name}")
        return api_client, report_client, email_config
        
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        raise
    except ApiException as e:
        print(f"API Error: {e}")
        raise
    except Exception as e:
        print(f"Error connecting to Rapid7: {e}")
        raise


def send_email_alert(subject, body, recipient_email, sender_email, attachment=None):
    """ Send an email alert using the mail command. """

    # Construct the mail command
    command = f'echo "{body}" | mail -s "{subject}" -a "From: {sender_email}" {recipient_email}'
    
    if attachment:
        command += f' -A {attachment}'  # Attach file if provided

    try:
        # Run the command using subprocess
        subprocess.run(command, shell=True, check=True)
        print(f"Email sent successfully to {recipient_email}")
    except subprocess.CalledProcessError as e:
        print(f"Error sending email: {e}")
        
        
# Track engines that have already triggered an alert
engine_alerts = {}

def check_engine_statuses():
    """Check the status of all scan engines and send an alert if any are down."""
    
    global engine_alerts

    try:
    # Connect to Rapid7
        api_client, report_client, email_config = setup_rapid7("/opt/nexpose_report_automation/nexposeScriptsForTesting/alert_script_config.xml", "Nexpose1") # Change the confix.xml path to the actual path

        endpoint = f"{api_client.configuration.host}/api/3/scan_engines"
        headers = {
                "Authorization": f"Basic {base64.b64encode(f'{api_client.configuration.username}:{api_client.configuration.password}'.encode()).decode()}",
                "Content-Type": "application/json"
            }
            
        response = requests.get(endpoint, headers=headers, verify=False)
        response.raise_for_status()

        engines = response.json()["resources"]

        for engine in engines:
            engine_name = engine["name"]
            engine_status = engine["status"]
            engine_id = engine["id"]

            if engine_status != "active":
                if engine_id not in engine_alerts:
                    # Send alert only once when status changes from active
                    subject = f"Alert: Scan Engine Down - {engine_name}, ID: {engine_id}"
                    body = f"The scan engine '{engine_name}' (ID: {engine_id}) is currently {engine_status}. Please investigate."
                    

                    # Use send_email_alert to send the alert
                    send_email_alert(
                        subject=subject,
                        body=body,
                        recipient_email=email_config["recipient_email"],  
                        sender_email=email_config["sender_email"],        
                        attachment=None                                    # Optional, provide an attachment path if needed
                    )
                    engine_alerts[engine_id] = True  # Mark alert as sent
            else:
                # Reset alert status when engine becomes active again
                if engine_id in engine_alerts:
                    del engine_alerts[engine_id]

    except Exception as e:
        print(f"Error checking engine statuses: {e}")
        return {}
        

def schedule_checks():
    """Schedule periodic checks."""
    
    while True:
       check_engine_statuses()
       time.sleep(60)  # Wait 1 minute



if __name__ == "__main__":
    schedule_checks()