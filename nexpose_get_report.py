from __future__ import print_function
import sys
import os
import subprocess
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(dir_path)
import rapid7vmconsole
import base64
import logging
from pathlib import Path
import re
from pprint import pprint
from rapid7vmconsole.rest import ApiException
import datetime
import urllib3
import pandas as pd
import glob
from time import sleep
from xml.etree import ElementTree as ET
# import openpyxl
# from openpyxl import load_workbook
# import openpyxl.formatting.rule
# from openpyxl.formatting.rule import ColorScaleRule, CellIsRule, FormulaRule
# from openpyxl.styles import Border, Side
# from openpyxl import styles
import os.path
urllib3.disable_warnings()
config = rapid7vmconsole.Configuration(name='Rapid7')
#Getting the config parameters in config.xml
config_file= ET.parse("/path/to/your/config/file")
root=config_file.getroot()
baseline_report_id=0
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
now = datetime.datetime.now()
date_time = now.strftime("%Y-%m-%d_%H-%M-%S")
t = now.strftime("%H-%M")
today = datetime.datetime.today()
week_num = today.isocalendar()[1]
year = now.strftime("%Y")
year = now.strftime("%Y")
month = now.strftime("%m")
folder_name =f'{year}-{week_num}'
id = [] # List contain all the site ID
name = [] # List contain all the site NAME
flag = 0 # Use to select correct query.

#Client Authentication
for server in root.findall('server'):
    if server.get('name') == sys.argv[1]:
        config.username=server.find('username').text
        config.password=server.find('password').text
        config.host=server.find('host').text
        config.api_key=server.find('api_key').text
        baseline_report_id = server.find('baseline_report_id').text
        log_file = server.find('log_file').text
        log_file_2 = server.find('log_file_2').text
        folder_path = server.find('folder_path').text
        destination = server.find('destination').text
        path_csv_to_check = server.find('path_csv_to_check').text
        output_csv_path = server.find('output_csv_path').text
        warningfile = server.find('warningfile').text
        warningfile2 = server.find('warningfile2').text
        destination_opt2 = server.find('destination_opt2').text
        path_csv_to_check2 = server.find('path_csv_to_check2').text
        path_csv_delta = server.find('path_csv_delta').text
        sid_path = server.find('sid_path').text
        report_id = server.find('report_id').text
        report_name = server.find('report_name').text
        deltacheck = server.find('deltacheck').text
        log_file_debug = server.find('log_file_debug').text
        if sys.argv[2] == "3":
            output_csv_path3 = server.find('output_csv_path3').text
            path_csv_delta3 = server.find('path_csv_delta3').text
            output_site_path = server.find('output_site_path').text
            sid_path3 = server.find('sid_path3').text
            log_file_3 = server.find('log_file_3').text
            deltacheck3 = server.find('deltacheck3').text
            output_excel_path = server.find('output_excel_path').text
        else:
            pass
for command in root.findall('sql_query'):
        query = command.find('query').text
        query_2 = command.find('query_2').text
        query_asset = command.find('query_asset').text
        query_fmm_montly = command.find('query_fmm_montly').text
        query_fmm_montly_2 = command.find('query_fmm_montly_2').text


auth = "%s:%s" % (config.username, config.password) 
auth = base64.b64encode(auth.encode('ascii')).decode()
client = rapid7vmconsole.ApiClient(configuration=config)
client.default_headers['Authorization'] = "Basic %s" % auth
report_client = rapid7vmconsole.ReportApi(client)

if len(sys.argv) <=4:
    if sys.argv[1].lower() == "nexpose1" :
        folder_path = f'{folder_path}{folder_name}/{sys.argv[1].lower()}'
        os.makedirs(folder_path,exist_ok=True) #don't rase error when folder exist
        path_csv_delta = f'{path_csv_delta.replace("{}",date_time)}'
        output_csv_path = f'{folder_path}{output_csv_path.replace("{}",date_time)}'
        # print(output_csv_path)
        os.makedirs(path_csv_to_check2,exist_ok=True)
    elif sys.argv[1].lower() == "nexpose2":
        folder_path = f'{folder_path}{folder_name}/{sys.argv[1].lower()}'
        os.makedirs(folder_path,exist_ok=True) #don't rase error when folder exist
        path_csv_delta = f'{path_csv_delta.replace("{}",date_time)}'
        output_csv_path = f'{folder_path}{output_csv_path.replace("{}",date_time)}'
        # print(output_csv_path)
        os.makedirs(path_csv_to_check2,exist_ok=True)
    else:
        print("Please indicate the right nexpose: Nexpose1 or Nexpose2")
        sys.exit()
    if sys.argv[2] == "1":
        opt = 1
        destination = destination
        path_csv_to_check =path_csv_to_check
        log_file = log_file
        warningfile = f'{warningfile.replace("{}",month)}'
        print(destination)
        print(path_csv_to_check)
        print(log_file)
    elif sys.argv[2] == "2":
        opt = 2
        destination = f'{destination_opt2.replace("{}",month)}'
        path_csv_to_check =path_csv_to_check2
        log_file = log_file_2
        warningfile = f'{warningfile2.replace("{}",month)}'
        print(destination)
        print(path_csv_to_check)
        print(log_file)
        print(warningfile)
    elif sys.argv[2] =="3" and sys.argv[1].lower() == "nexpose1":
        opt = 3
        ##### USE FOR OPTION 3
        output_csv_path3 = f'{output_csv_path3.replace("{year}",year).replace("{month}",month).replace("{t}",t)}'
        path_csv_delta3 = f'{path_csv_delta3.replace("{date_time}",date_time).replace("{t}",t)}'
        # List of Fremantle site ID
        deltacheck = deltacheck3
        output_excel_path = f'{output_excel_path.replace("{year}",year).replace("{month}",month).replace("{t}",t)}'
        output_csv_path = output_csv_path3
        sid_path = sid_path3
        log_file = log_file_3
        path_csv_delta = path_csv_delta3
        print(f'output_csv_path  {output_csv_path}')
        print(f'sid_path  {sid_path}')
        print(f'log_file  {log_file}')
        print(f'path_csv_delta  {path_csv_delta}')
    elif sys.argv[2] =="3" and sys.argv[1].lower() != "nexpose1":
        print("Option 3 only work with Nexpose1. Please set NexposeID = Nexpose1")
        sys.exit()
    else:
        print("Please indicate the running option: 1 for generate report | 2 for check assets | 3 for generate FMM report monthly (Only work with Nexpose1)")
        sys.exit()
elif len(sys.argv) <3 or len(sys.argv) >4:
    print("Usage: python3 v2new_get_report.py <Nexpose ID> <Option> <debug>")
    print("Nexpose ID: Nexpose1 | Nexpose2 \nOption: 1 for generate report | 2 for check assets | 3 for generate FMM report monthly")
    print("Using -v for debug mode")
    sys.exit()


def run_report(client, report_id):
    report = client.generate_report(report_id)
    return report.id

def generate_report(x,report_client,report_id,client,flag,opt,query,query_2,query_asset,query_fmm_montly,query_fmm_montly_2):
    client = client
    flag = flag
    opt = opt
    report_name = "ISS-Testing"
    report_id =report_id
    if opt == 1:
        if flag == 0:
            id = x
            # query = f'{query}'
            query = f'{query.replace("{id}", id)}'
            logger.debug(f'Generating Report for: {x}')
            logger.debug(f'Query:   {query}')
            # print(query)
        else:
            query = query_2
            logger.debug(f'Query:   {query}')
    elif opt == 2:
        query = query_asset
        logger.debug(f'Query:   {query}')
    elif opt == 3:
            if flag == 0:
                id = x
                query = f'{query_fmm_montly.replace("{id}", id)}'
                logger.debug(f'Generating Report for: {x}')
                logger.debug(f'Query:   {query}')
            else:
                query = query_fmm_montly_2
                logger.debug(f'Query:   {query}')
    report_config = rapid7vmconsole.Report(name=report_name, format='sql-query', query=query, version='2.3.0')
    response = report_client.update_report(id= report_id, report=report_config)

def download_report(client, report_id, instance_id,destination):
    report_done = False
    while not report_done:
        report_instance_status = client.get_report_instance(report_id, instance_id).status

        if any(report_instance_status in s for s in ['aborted', 'failed', 'complete']):
            report_done = True
            report_contents = client.download_report(report_id, instance_id)
            pprint("Created in %s" % destination)
            logger.info("Created in %s" % destination)
            text_file = open(destination, "w",encoding='ISO-8859-1')
            text_file.write(report_contents)
            text_file.close()
            # return report_contents
            logger.debug(f'Downloading Report for: {report_instance_id}')
            logger.debug(report_contents)
            logger.info(f'Report Id {report_id} is running, waiting for download')
        else:
            sleep(40)



def add_csv(destination,logger,output_csv_path,x,y):
    try:
        ID=x
        Name=y
        df = pd.read_csv(destination,sep=',')
        logger.debug(df)
        row = df.loc[df['status'] == 'Remediated']
        new_df = pd.DataFrame({'id': ID,'Name': Name , 'Remediated': [row['count'].iloc[0]], 'New': [df.loc[df['status'] == 'New']['count'].iloc[0]]})
        logger.debug(new_df)
        new_df.to_csv(output_csv_path, index=False,mode='a',header=False)
    except Exception as e:
        logger.exception(e)

def finalize_csv(logger,output_csv_path):
    try:
        df = pd.read_csv(output_csv_path,header=None)
        df.columns = ["id","Name", "Remediated", "New"]
        logger.debug(df)
        df.drop(['Name'],axis=1).to_csv(output_csv_path,index=False)
    except Exception as e:
        logger.exception(e)

def final_output(output_csv_path,path_csv_delta,logger):
    try:
        df1 = pd.read_csv (path_csv_delta)
        x= pd.read_csv (output_csv_path)
        df2 = pd.read_csv(output_csv_path)
        df3 = pd.merge (df1, df2, on = 'id')
        df3.rename(columns={"Remediated": "Remediated Vuln", "New": "New Vuln"}).to_csv (output_csv_path,index=False)
    except Exception as e:
        logger.exception(e)




        
def delta(destination,path_csv_to_check,logger,deltacheck,warningfile):
    print(f'PATH TO CHECK: {path_csv_to_check}')
    csv_files = glob.glob(path_csv_to_check + deltacheck)
    logger.debug(csv_files)
    try:
        if len(csv_files) ==1:
            csvfile = csv_files[0]
            df = pd.read_csv(csvfile, sep=",")
            df.to_csv(destination,index=False)
        else:
            csv_files.sort(key=os.path.getmtime,reverse=True)
            latest_file = csv_files[0]
            print(f'New file: {latest_file}')
            second_latest_file = csv_files[1]
            print(f'Seccond file: {second_latest_file}')
            df_old = pd.read_csv(second_latest_file, sep = ",")
            df_new = pd.read_csv(latest_file, sep = ",")
            df = pd.merge(df_new, df_old, on="id", suffixes=("_1", "_2"))
            df["Delta Risk"] = df["Total Risk_1"] - df["Total Risk_2"]
            df["delta_percentage"] = (df["Delta Risk"] / df["Total Risk_2"]) * 100
            df["delta_percentage"] = df["delta_percentage"].round(2)
            df["Delta Critical"] = df["Total Critical Vulnerabilities_1"] -df["Total Critical Vulnerabilities_2"]
            df.columns = df.columns.str.replace("_1","")
            df = df.loc[:, ~df.columns.str.contains('_2')]
            # df.drop(columns=["id"]).to_excel(destination,sheet_name="Overview", index=False,freeze_panes=(1,1))
            # df.to_csv(destination,index=False)
            if sys.argv[2] == "1":
                check = os.path.isfile(warningfile)
                if check == True:
                    mode = "a"
                else:
                    mode = "w"
                with open(warningfile, mode) as f:            
                    for index,row in df.iterrows():
                        if float(row['delta_percentage']) < 0:
                            trend = "Decrease"
                        else:
                            trend = "Increase"
                        if 10 <= abs(row['delta_percentage']) < 40:
                            f.write(f'{date_time}   {row["Site"]}: {trend} around {row["delta_percentage"]}% in the Delta Risk score\n')
                            f.write(f'{date_time}   Please check result file for more detail: {destination} \n')
                            f.write(f'{"#"*40}\n')
                        elif abs(row['delta_percentage']) >= 40:
                            f.write(f'{date_time}   !!!!!! Warning {row["Site"]}: SIGNIFICANT {trend} around {row["delta_percentage"]}% in the Delta Risk score\n')
                            f.write(f'{date_time}   Please check log for more detail: {destination} \n')
                            f.write(f'{"#"*40}\n')
                        # elif abs(row['delta_percentage']) == 0:
                        #     f.write(f'{date_time}   NO change in Delta Risk score\n')
                        #     f.write(f'{"#"*40}\n')
                        else:
                            pass
            else:
                pass
            df.drop(columns=["delta_percentage"]).to_csv(destination,index=False)
    except Exception as e:
        logger.exception(e)



################################
#                              #
#     Check Assets Option2     #
#                              #
################################
def check_warningfile_exsit(warningfile):
    check = os.path.isfile(warningfile)
    if check == True:
        x = "a"
        return x
    else:
        x = "w"
        return x
def analyze_assets(x,warningfile,path_csv_to_check):
    csv_files = glob.glob(path_csv_to_check + '/*_assets_*.csv')
    logger.debug(csv_files)
    logger.debug(f'TextIOWrapper MODE {x}')
    with open(warningfile, x) as f:
        if len(csv_files) ==1:
            pass
        else:
            csv_files.sort(key=os.path.getmtime,reverse=True)
            latest_file = csv_files[0]
            logger.debug(f'New file: {latest_file}')
            second_latest_file = csv_files[1]
            logger.debug(f'Seccond file: {second_latest_file}')
            df_old = pd.read_csv(second_latest_file, sep = ",")
            df_new = pd.read_csv(latest_file, sep = ",")
            total_assets_old = df_old['Total Assets'].sum()
            total_assets_new = df_new['Total Assets'].sum()
            percentage = ((total_assets_new - total_assets_old) / total_assets_old) * 100
            if percentage < 0:
                x = "Decrease"
            else:
                x = "Increase"
            if abs(percentage) >= 20:
                print(f'Warning there are some: {x} around {percentage}% in the total Assets')
                f.write(f'{date_time}   Warning there are some: {x} around {percentage}% in the total Assets\n')
                f.write(f'{date_time}   Please check log for more detail: {destination} \n')
                f.write(f'{"#"*40}\n')
            elif 10 <= percentage < 20:
                print(f'Warning there are some: {x} around {percentage}% in the total Assets')
                f.write(f'{date_time}   Warning there are some: {x} around {percentage}% in the total Assets\n')
                f.write(f'{date_time}   Please check log for more detail: {destination} \n')
                f.write(f'{"#"*40}\n')
            elif percentage == 0:
                print('NO change in assets')
                f.write(f'{date_time}   NO change in assets\n')
                f.write(f'{"#"*40}\n')
            else:
                print(f'The {x} {percentage} percentage is insignificant')
                f.write(f'{date_time}   The {x} {percentage} percentage is insignificant\n')
                f.write(f'{"#"*40}\n')
    f.close

################################
#                              #
#      FMM REPORT Option 3     #
#                              #
################################


#Conditional Formatting
def color_fmm(output_csv_path):
    df = pd.read_csv(output_csv_path)
    if sys.argv[2] == 3:
        if 'Delta Risk' in df.columns or 'Delta Critical' in df.columns:
            df = df[['id','Site','Total Assets','Total Vulnerabilities Discovered','Total Critical Vulnerabilities','Total Severe Vulnerabilities','Total Moderate Vulnerabilities','New Vuln','Remediated Vuln','Delta Critical','Total Risk','Average risk','Delta Risk']]
            df.drop(columns=["id"]).rename(columns={"Remediated Vuln": "Total Remediated last month", "New Vuln": "New Vulnerabilities Discovered"}).sort_values("Total Vulnerabilities Discovered",ascending=False).to_excel(output_excel_path, sheet_name="Overview",index=False)
        else:    
            df.drop(columns=["id"]).rename(columns={"Remediated Vuln": "Total Remediated last month", "New Vuln": "New Vulnerabilities Discovered"}).sort_values("Total Vulnerabilities Discovered",ascending=False).to_excel(output_excel_path, sheet_name="Overview",index=False)
        # green_fill = styles.PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type='solid')
        # red_fill = styles.PatternFill(start_color='FF0000', end_color='FF0000', fill_type='solid')
        # yellow_fill = styles.PatternFill(start_color='FFFF00', end_color='FFFF00', fill_type='solid')
        # wb = openpyxl.load_workbook (output_excel_path)
        # sheet_to_focus = 'Overview'
        # for sheet in wb.worksheets:
        #     if sheet.title != sheet_to_focus:
        #         wb.active = sheet
        #         # sheet.conditional_formatting.add('E1:E100',ColorScaleRule(start_type='min', start_color='C6EFCE',mid_type='percentile', mid_value=50, mid_color='FFEB9C',end_type='max', end_color='FFC7CE'))
        #         wb.save (output_excel_path)  
        #     else:
        #         wb.active = sheet
        #         for row in wb.active.iter_rows(min_row=2, max_row=100, min_col=11, max_col=12):
        #             for cell in row:
        #                 if cell.value is not None and int(cell.value) == 0:
        #                     cell.fill = yellow_fill
        #                 elif cell.value is not None and int(cell.value) > 0:  
        #                     cell.fill = red_fill
        #                 elif cell.value is not None and int(cell.value) < 0:
        #                     cell.fill = green_fill
        #         thick = Side(border_style="thick", color="000000")
        #         double = Side(border_style="double", color="000000")    
        #         range=sheet['K1':'L100']
        #         for cell in range:
        #             for x in cell:
        #                 if x.value != None:            
        #                     x.border=Border(top=thick, left=thick, right=thick, bottom=thick)
        #                 else:
        #                     pass
        #         font = openpyxl.styles.Font (color='FFFFFF', bold=True)
        #         fill = openpyxl.styles.PatternFill (patternType='solid', fgColor='23cc36')
        #         for sheet in wb.worksheets:
        #             row = sheet [1]
        #             for cell in row:
        #                 cell.font = font
        #                 cell.fill = fill
        #         wb.save (output_excel_path)                
    else:
        if 'Delta Risk' in df.columns or 'Delta Critical' in df.columns:
            df = df[['id','Site','Total Assets','Total Vulnerabilities Discovered','Total Critical Vulnerabilities','Total Severe Vulnerabilities','Total Moderate Vulnerabilities','New Vuln','Remediated Vuln','Delta Critical','Total Risk','Average risk','Delta Risk']]
            df.drop(columns=["id"]).rename(columns={"Remediated Vuln": "Total Remediated last week", "New Vuln": "New Vulnerabilities Discovered"}).sort_values("Total Vulnerabilities Discovered",ascending=False).to_csv(output_csv_path, index=False)
        else:
            df.drop(columns=["id"]).rename(columns={"Remediated Vuln": "Total Remediated last week", "New Vuln": "New Vulnerabilities Discovered"}).sort_values("Total Vulnerabilities Discovered",ascending=False).to_csv(output_csv_path, index=False)         

def color(output_csv_path):
    df = pd.read_csv(output_csv_path)
    if 'Delta Risk' in df.columns or 'Delta Critical' in df.columns:
        df = df[['id','Site','Total Assets','Total Vulnerabilities Discovered','Total Critical Vulnerabilities','Total Severe Vulnerabilities','Total Moderate Vulnerabilities','New Vuln','Remediated Vuln','Delta Critical','Total Risk','Average risk','Delta Risk']]
        df.drop(columns=["id"]).rename(columns={"Remediated Vuln": "Total Remediated last week", "New Vuln": "New Vulnerabilities Discovered"}).sort_values("Total Vulnerabilities Discovered",ascending=False).to_csv(output_csv_path, index=False)
    else:
        df.drop(columns=["id"]).rename(columns={"Remediated Vuln": "Total Remediated last week", "New Vuln": "New Vulnerabilities Discovered"}).sort_values("Total Vulnerabilities Discovered",ascending=False).to_csv(output_csv_path, index=False)      


def send_email(week_num,year,output_csv_path,warningfile):
    most_recent_date = None
    relevant_lines = []
    with open(warningfile, 'r') as file:
        lines = file.readlines()
    for line in lines:
        if 'in the Delta Risk score' in line:
            date_str = line.split()[0]  # Extract the date part
            try:
                if most_recent_date is None or date_str > most_recent_date:
                    most_recent_date = date_str
                    relevant_lines = [line]
                elif date_str == most_recent_date:
                    relevant_lines.append(line)
            except ValueError:
                pass
    # Create a temp file for the body of the email
    with open('/path/to/temp/processing/file','w') as f:
        for line in relevant_lines:
            logger.debug(line.strip())
            f.write(line)              
    command = f'(mail -s "Weekly report for {sys.argv[1]} on week {week_num} year {year}" -a "From: SENDER-EMAIL" RECIPIENT-EMAIL -A {output_csv_path} < /path/to/temp/processing/file )'
    subprocess.run(command, shell=True)
    # Remove the temp file 
    os.remove('/path/to/temp/processing/file')

def send_email_fmm(month,year,output_excel_path):             
    command = f'(echo "Please find attachment for more information" | mail -s "Montly report for {sys.argv[1]} on week {month} year {year}" -a "From: SENDER-EMAIL" RECIPIENT-EMAIL -A {output_excel_path}) '
    subprocess.run(command, shell=True)



def remove_file(destination,path_csv_delta):
    os.remove(destination)
    os.remove(path_csv_delta)
if __name__ == '__main__':
    if "-v" in sys.argv:
        logging.basicConfig(filename=log_file_debug, level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filemode='w')
    else:
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logger = logging.getLogger(__name__)
    try:
        logger.info(f'################################\n                           #            START             #\n                           ################################')
        #ALL SITE REPORT WEEKLY
        if sys.argv[2] == "1":
            with open(sid_path,'r') as f:
                lines = f.readlines()
            for element in lines:
                id.append(element.split(":")[0])
                name.append(element.strip().split(":")[1])
            for id_value,name_value in zip(id,name):
                x = str(id_value) #x: Site ID
                y = str(name_value)#y: Site NAME        
                logger.info(f'Generating Report for: {x}')
                generate_report(x,report_client,report_id,client,flag,opt,query,query_2,query_asset,query_fmm_montly,query_fmm_montly_2)
                logger.info(f'Running Report for: {x}')
                report_instance_id = run_report(report_client, report_id)
                logger.info(f'Downloading Report for: {report_instance_id}')
                download_report(report_client, report_id, report_instance_id,destination)
                logger.info(f'Download COmpleted')
                logger.info(f'ADD CSV: {x} {y} ')
                add_csv(destination,logger,output_csv_path,x,y)
            logger.info(f'FINALIZE CSV ')
            finalize_csv(logger,output_csv_path)
            #Start Delta Calculation#
            logger.info(f'START DELTA STEP')        
            flag= 1
            generate_report(x,report_client,report_id,client,flag,opt,query,query_2,query_asset,query_fmm_montly,query_fmm_montly_2)
            logger.info(f'Running delta report')
            report_instance_id = run_report(report_client, report_id)
            logger.info(f'Downloading Report')
            #Use the temp variable to save the original destination for delta function use latter
            temp = destination
            destination = path_csv_delta
            logger.debug(destination)
            download_report(report_client, report_id, report_instance_id,destination)
            logger.info(f'Processing Delta')
            delta(destination,path_csv_to_check,logger,deltacheck,warningfile)
            logger.info('Final output')
            final_output(output_csv_path,path_csv_delta,logger)
            logger.info('Add color')
            color(output_csv_path)
            logger.info('Send Email')
            send_email(week_num,year,output_csv_path,warningfile)
        # START GET ASSETS REPORT 
        elif sys.argv[2] == "2":
            logger.info('Generate Assets report')
            x=""
            generate_report(x,report_client,report_id,client,flag,opt,query,query_2,query_asset,query_fmm_montly,query_fmm_montly_2)
            logger.info('Run Report')
            report_instance_id = run_report(report_client, report_id)        
            download_report(report_client, report_id, report_instance_id,destination)
            logger.info('Check warning file exist')
            x=check_warningfile_exsit(warningfile)
            analyze_assets(x,warningfile,path_csv_to_check)
        # START FMM REPORT MONTHLY
        elif sys.argv[2] == "3":
            with open(sid_path,'r') as f:
                lines = f.readlines()
            for element in lines:
                id.append(element.split(":")[0])
                name.append(element.strip().split(":")[1])
            for id_value,name_value in zip(id,name):
                x = str(id_value) #x: Site ID
                y = str(name_value)#y: Site NAME        
                logger.info(f'Generating Report for: {y}')
                generate_report(x,report_client,report_id,client,flag,opt,query,query_2,query_asset,query_fmm_montly,query_fmm_montly_2)
                logger.info(f'Running Report for: {y}')
                report_instance_id = run_report(report_client, report_id)
                logger.debug(f'Downloading Report for: {report_instance_id}')
                logger.info(f'Downloading Report')
                download_report(report_client, report_id, report_instance_id,destination)
                logger.debug(f'Download COmpleted')
                logger.info(f'Download COmpleted')
                logger.info(f'ADD CSV: {y} ')
                add_csv(destination,logger,output_csv_path,x,y)
            logger.info(f'FINALIZE CSV ')
            finalize_csv(logger,output_csv_path)
            #Start Delta Calculation#
            logger.info(f'START DELTA STEP')        
            flag= 1
            generate_report(x,report_client,report_id,client,flag,opt,query,query_2,query_asset,query_fmm_montly,query_fmm_montly_2)
            logger.info('Running delta report')
            report_instance_id = run_report(report_client, report_id)
            logger.info('Downloading Report')
            #Use the temp variable to save the original destination for delta function use latter
            temp = destination
            destination = path_csv_delta
            print(destination)
            download_report(report_client, report_id, report_instance_id,destination)
            logger.info(f'Processing Delta')
            delta(destination,path_csv_to_check,logger,deltacheck,warningfile)
            logger.info('Final output')
            final_output(output_csv_path,path_csv_delta,logger)
            logger.info('Add color')
            color_fmm(output_csv_path)
            logger.info('Send email')
            send_email_fmm(month,year,output_excel_path)
        logger.info(f'################################\n                           #             DONE             #\n                           ################################')
    except Exception as e:
        logger.exception(e)
