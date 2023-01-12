from __future__ import print_function
import sys
import os
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(dir_path)

import rapid7vmconsole
import base64
import logging
from pathlib import Path
import re
from pprint import pprint
from rapid7vmconsole.rest import ApiException
import time
from datetime import datetime, timedelta
import urllib3
import csv
import pandas as pd
import numpy as np
from xml.etree import ElementTree as ET
urllib3.disable_warnings()

config = rapid7vmconsole.Configuration(name='Rapid7')
#Getting the config parameters in config.xml
config_file= ET.parse("config.xml")
root=config_file.getroot()
baseline_report_id=0
for server in root.findall('server'):
    if server.get('name') == sys.argv[2]:
        config.username=server.find('username').text
        config.password=server.find('password').text
        config.host=server.find('host').text
        config.api_key=server.find('api_key').text
        baseline_report_id = server.find('baseline_report_id').text
config.verify_ssl = False
config.assert_hostname = False
config.proxy = None
config.ssl_ca_cert = None
config.connection_pool_maxsize = None
config.cert_file = None
config.key_file = None
config.safe_chars_for_path_param = ''
config.debug = False

sys.tracebacklimit = 0
#Client Authentication
auth = "%s:%s" % (config.username, config.password) 
auth = base64.b64encode(auth.encode('ascii')).decode()
client = rapid7vmconsole.ApiClient(configuration=config)
client.default_headers['Authorization'] = "Basic %s" % auth
#Variables setup for getting reports on defined days and creating folders
weekDays = {"Monday":0,"Tuesday":1,"Wednesday":2,"Thursday":3,"Friday":4,"Saturday":5,"Sunday":6}
week= datetime.now().isocalendar()[1]
year= datetime.now().year
day=sys.argv[1]
today = datetime.today()
path= str(year)+ "-" + str(week)+'/'+str(day)
Path(str(path)).mkdir(parents=True, exist_ok=True)

#This function read the provided generated csv files for each report and will display the statistics for this week report.
def Analyze_Baseline(File,Name):

    data= pd.read_csv(File)
    data['current_scan_datetime'] = pd.to_datetime(data['current_scan_datetime'], format = '%Y-%m-%d %H:%M:%S.%f')
    
    Remediated = data[(data.status == 'Remediated') & ((datetime.today() - data.current_scan_datetime).dt.days < 5)].groupby('status').size()
    if hasattr(Remediated, 'Remediated'):
        Remediated = Remediated.Remediated
    else:
        Remediated  = 0 

    Critical = data[(data.cvss_score > 8) & ((datetime.today() - data.current_scan_datetime).dt.days < 5)].groupby('status').size()
    if hasattr(Critical, 'New'):
        Critical = Critical.New
    else:
        Critical = 0    

    Severe = data[(data.cvss_score > 4) & (data.cvss_score <8) & ((datetime.today() - data.current_scan_datetime).dt.days < 5)].groupby('status').size()
    if hasattr(Severe, 'New'):
        Severe = Severe.New
    else:
        Severe = 0   

    s = f"""
    {'-'*40}
    # Statistics for this week:
    # Scope: {Name}
    # New Critical: {Critical}
    # New Severe: {Severe}
    # Remediated: {Remediated}    

    {'-'*40}
    """

    print(s)

#This function download the reports generated between 00:01 and 23:59 on a given day 
def download_reports(Day):

    page = 0 # int | The index of the page (zero-based) to retrieve. (optional) (default to 0)
    size = 400 # int | The number of records per page to retrieve. (optional) (default to 10)
    sort = ['ID,DESC'] # list[str] | The criteria to sort the records by, in the format: `property[,ASC|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. (optional)
    api_instance = rapid7vmconsole.ReportApi(client)
    api_response = api_instance.get_reports(page=page, size=size, sort=sort)
    #pprint(api_response)
    for a in api_response.resources:
        #print("ID: %s; name: %s; owner: %s, site: %s" % (a.id, a.name, a.owner, a.scope.sites))
        if (a.id != int(baseline_report_id) and a.scope.sites != None):
            IDreport= a.id
            name= a.name
            api_response = api_instance.get_report_instances(id=a.id)
            Site = a.scope.sites
            if len(Site) == 1:
                Site = Site[0]
                for a in api_response.resources:
                    date = re.sub('.[^.]+Z','',a.generated)
                    if (date != ''):
                        try:
                            date= datetime.strptime(date, '%Y-%m-%dT%H:%M:%S')
                            #delta= (datetime.now()-date).days
                            date_of_report_to_download = today - timedelta(days=today.weekday()-weekDays[Day])
                            if date_of_report_to_download > today:
                                date_of_report_to_download = date_of_report_to_download - timedelta(days=7) #the Week before
                            delta = (date_of_report_to_download - date).days
                            if ( datetime.combine(date_of_report_to_download, datetime.min.time()) <= date <= datetime.combine(date_of_report_to_download, datetime.max.time()) ):
                                api_response = api_instance.download_report(id=IDreport, instance=a.id)
                                text_file = open(path + "/" + name + '-'+ str(year)+ '-'+ str(week)+'.pdf', "w",encoding='ISO-8859-1')
                                text_file.write(api_response)
                                text_file.close()
                                if "Audit" in name:
                                    generate_compare_report(Site)  
                        except ValueError as e:
                            print('ValueError:', e)
     
#This function is not used by default, only if required an automated way to change owners
def change_owner():
    
    page = 0 # int | The index of the page (zero-based) to retrieve. (optional) (default to 0)
    size = 400 # int | The number of records per page to retrieve. (optional) (default to 10)
    sort = ['ID,DESC'] # list[str] | The criteria to sort the records by, in the format: `property[,ASC|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. (optional)
    api_instance = rapid7vmconsole.ReportApi(client)
    api_response = api_instance.get_reports(page=page, size=size, sort=sort)
    #To change all report of a owner to nxuser
    for a in api_response.resources:
        print("ID: %s; name: %s; owner: %s" % (a.id, a.name, a.owner))
        if a.owner == 9: #target one specific user to reattribute
            a.owner = 28
            api_response = api_instance.update_report(id=a.id, report=a)
            pprint(api_response)

#This function use on each Nexpose Console a predefined CSV report with SQL Query (see baseline_report_id) to generate the comparison report and download it.
def generate_compare_report(site):
    
    page = 0 # int | The index of the page (zero-based) to retrieve. (optional) (default to 0)
    size = 400 # int | The number of records per page to retrieve. (optional) (default to 10)
    sort = ['ID,DESC'] # list[str] | The criteria to sort the records by, in the format: `property[,ASC|DESC]`. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. (optional)
    api_instance = rapid7vmconsole.ReportApi(client)
    api_site_instance = rapid7vmconsole.SiteApi(client)
    site = api_site_instance.get_site(site)
    site_name = site.name
    
    api_response = api_instance.get_reports(page=page, size=size, sort=sort)

    for a in api_response.resources:
        #print("ID: %s; name: %s; owner: %s" % (a.id, a.name, a.owner))
        #print(baseline_report_id)
        if a.id == int(baseline_report_id): #the baseline report is 11453, SQL is 11884
            IDreport = a.id
            name = site_name
            a.query="with assets_vulns as (\nSELECT\nfasv.asset_id,\nfasv.vulnerability_id,\nbaselineComparison (fasv.scan_id, current_scan) AS baseline,\ns.baseline_scan,\ns.current_scan\nFROM\nfact_asset_scan_vulnerability_instance fasv\nJOIN (\nSELECT\nasset_id,\npreviousScan (asset_id) AS baseline_scan,\nlastScan (asset_id) AS current_scan\nFROM\ndim_asset\nJOIN dim_site_asset dsa USING (asset_id) \nWHERE dsa.site_id = "+ str(site.id)+"\n) s ON s.asset_id = fasv.asset_id\nAND (\nfasv.scan_id = s.baseline_scan\nOR fasv.scan_id = s.current_scan\n)\nGROUP BY\nfasv.asset_id,\nfasv.vulnerability_id,\ns.baseline_scan,\ns.current_scan\nHAVING\n(\nbaselineComparison (fasv.scan_id, current_scan) = 'Same'\n)\nOR (\nbaselineComparison (fasv.scan_id, current_scan) = 'New'\n)\nOR (\nbaselineComparison (fasv.scan_id, current_scan) = 'Old'\n)\n),\nbaseline_scan_date as (\nSELECT\nav.asset_id,\nfinished\nFROM assets_vulns av\nLEFT JOIN dim_scan ds ON ds.scan_id = av.baseline_scan\nGROUP BY av.asset_id, finished\n),\n \ncurrent_scan_date as (\nSELECT\nav.asset_id,\nfinished\nFROM assets_vulns av\nLEFT JOIN dim_scan ds ON ds.scan_id = av.current_scan\nGROUP BY av.asset_id, finished\n),\nnew_vulns as (\nSELECT\nav.asset_id,\nav.vulnerability_id,\nCOUNT (av.vulnerability_id) AS new_vulns\nFROM\nassets_vulns AS av\nWHERE\nav.baseline = 'New'\nGROUP BY\nav.asset_id,\nav.vulnerability_id\n),\nremediated_vulns AS (\nSELECT\nav.asset_id,\nav.vulnerability_id,\nCOUNT (av.vulnerability_id) AS remediated_vulns\nFROM\nassets_vulns AS av\nWHERE\nav.baseline = 'Old'\nGROUP BY\nav.asset_id,\nav.vulnerability_id\n \n),\nvuln_exploit_count AS (\nSELECT\nCASE WHEN ec1.vulnerability_id IS NOT NULL THEN ec1.vulnerability_id ELSE ec2.vulnerability_id END as vulnerability_id, metasploit, exploitdb\nFROM\n(SELECT\nav.vulnerability_id,\nCOUNT(dve.source) as metasploit\nFROM assets_vulns av\nJOIN dim_vulnerability_exploit dve ON av.vulnerability_id = dve.vulnerability_id\nWHERE dve.source = 'Metasploit'\nGROUP BY\nav.vulnerability_id\n) ec1\n \nFULL JOIN\n \n(SELECT\nav.vulnerability_id,\nCOUNT(dve.source) as exploitdb\nFROM assets_vulns av\nJOIN dim_vulnerability_exploit dve ON av.vulnerability_id = dve.vulnerability_id\nWHERE dve.source = 'Exploit DB'\nGROUP BY\nav.vulnerability_id\n) ec2\n \nON ec2.vulnerability_id = ec1.vulnerability_id\n)\n \nSELECT\n'Remediated' as status,\nda1.ip_address AS ip_address,\nda1.host_name AS hostname,\nbsd.finished as baseline_scan_datetime,\ncsd.finished as current_scan_datetime,\ndv1.vulnerability_id,\ndv1.title,\nCAST(dv1.cvss_score as decimal(10,2)) as cvss_score,\nCAST(dv1.riskscore as decimal(10,0)) as riskscore,\ndv1.malware_kits,\nCASE WHEN vec.metasploit IS NULL THEN 0 ELSE vec.metasploit END as metasploit,\nCASE WHEN vec.exploitdb IS NULL THEN 0 ELSE vec.exploitdb END as exploitdb\nFROM\nremediated_vulns rv\nJOIN dim_asset da1 ON da1.asset_id = rv.asset_id\nLEFT JOIN baseline_scan_date bsd ON bsd.asset_id = da1.asset_id\nLEFT JOIN current_scan_date csd ON csd.asset_id = da1.asset_id\nJOIN dim_vulnerability dv1 ON dv1.vulnerability_id = rv.vulnerability_id\nLEFT JOIN vuln_exploit_count vec ON vec.vulnerability_id = rv.vulnerability_id\n \nUNION ALL\n \nSELECT\n'New' as status,\nda2.ip_address AS ip_address,\nda2.host_name AS hostname,\nbsd.finished as baseline_scan_datetime,\ncsd.finished as current_scan_datetime,\ndv2.vulnerability_id,\ndv2.title,\nCAST(dv2.cvss_score as decimal(10,2)) as cvss_score,\nCAST(dv2.riskscore as decimal(10,0)) as riskscore,\ndv2.malware_kits,\nCASE WHEN vec.metasploit IS NULL THEN 0 ELSE vec.metasploit END as metasploit,\nCASE WHEN vec.exploitdb IS NULL THEN 0 ELSE vec.exploitdb END as exploitdb\nFROM\nnew_vulns nv\nJOIN dim_asset as da2 ON da2.asset_id = nv.asset_id\nLEFT JOIN baseline_scan_date bsd ON bsd.asset_id = da2.asset_id\nLEFT JOIN current_scan_date csd ON csd.asset_id = da2.asset_id\nJOIN dim_vulnerability dv2 ON dv2.vulnerability_id = nv.vulnerability_id\nLEFT JOIN vuln_exploit_count vec ON vec.vulnerability_id = nv.vulnerability_id\nORDER BY status DESC, ip_address, hostname, title" 
            a.scope.sites = [site.id]
            api_response = api_instance.update_report(id=a.id, report=a)
            api_response = api_instance.generate_report(id=a.id)
            IDinstance = api_response.id
            generated_date = datetime.now()
            instance = api_instance.get_report_instances(id=a.id)
            api_response = ''
            pprint("Generating Comparison Report for %s" % name)
            while(api_response == ''):
                api_response = api_instance.download_report(id=IDreport, instance=IDinstance)
            destination = path + "/" + name + '-'+ str(year)+ '-'+ str(week)+'.csv'
            pprint("Created in %s" % destination)
            text_file = open(destination, "w",encoding='ISO-8859-1')
            text_file.write(api_response)
            text_file.close()
 
            for a in instance.resources:
                try:
                    api_response = api_instance.delete_report_instance(id=IDreport, instance=a.id)
                except ValueError as e:
                    print('ValueError:', e)                  

            Analyze_Baseline(destination,name)
            
def main():
    download_reports(sys.argv[1])
#Command: python3 get_report.py [Day] [Server]. Example: python3 get_report.py Sunday Nexpose1
if __name__ == "__main__":
    main()
