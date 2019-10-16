#!/usr/bin/env python
from tenable.sc import TenableSC
import pandas
from datetime import date

# Login to Tenable.sc
try:
    sc = TenableSC('IP ADDRESS')
    sc.login('USER_NAME', 'PASSWORD')
except:
    print ('Too Many logins in this credintials. Log in via browser to clear them. Then Log out and run the script.')
    quit()

scanid = input('Please enter the scan ID (eg: 1111): ')

try:
    
    ip_list = []
    ip_data_list = []
    vul_data_list = []
    software_list = []
    bulletines_list = []
    services_list = []
    port_list = []

    #Getting IPs
    for i in sc.analysis.scan(scanid, 
        tool='sumip'):
        ip = i['ip']
        ip_data = [ip, i['dnsName'], i['macAddress'], i['netbiosName'], i['policyName'], i['severityCritical'], i['severityHigh'], i['severityMedium'], i['severityLow'], i['severityInfo']]
        ip_list.append(ip)
        ip_data_list.append(ip_data)

    for z in ip_list:
        #Getting Vul Details
        for i in sc.analysis.scan(scanid, 
            ('ip', '=', z),
            tool='vulndetails'):
            cpe = i['cpe']
            if 'br' in cpe:
                cpex = cpe.split('<br/>')
                new_cpe = []
                for x in cpex:
                    new = x.replace('cpe:/','')
                    new_cpe.append(new)
                new_cpe = str(", ".join(new_cpe))
            else:
                new_cpe = cpe.replace('cpe:/','')

            if not int(i['vulnPubDate']) == -1:
                vulpubdate = date.fromtimestamp(int(i['vulnPubDate']))
            else: 
                vulpubdate = 'No Data'

            if not int(i['patchPubDate']) == -1:
                patchpubdate = date.fromtimestamp(int(i['patchPubDate']))
            else: 
                patchpubdate = 'No Data'

            data = [i['ip'], i['port'],i['protocol'],i['dnsName'], new_cpe, i['description'], i['synopsis'], i['cve'], i['severity']['description'], i['version'], i['solution'], vulpubdate, patchpubdate]
            vul_data_list.append(data)

        #Getting Software Details
        for j in sc.analysis.scan(scanid, 
            ('ip', '=', z),
            tool='listsoftware'):
            data = [z, j['name'], j['detectionMethod']]
            software_list.append(data)

        #Getting Bulletines Data
        for k in sc.analysis.scan(scanid, 
            ('ip', '=', z),
            tool='summsbulletin'):
            data = [z, k['msbulletinID'], k['severity']['description']]
            bulletines_list.append(data)

        #Getting Services Data
        for l in sc.analysis.scan(scanid, 
            ('ip', '=', z),
            tool='listservices'):
            data = [z, l['name'], l['detectionMethod']]
            services_list.append(data)

        #Getting Port Data
        for m in sc.analysis.scan(scanid, 
            ('ip', '=', z),
            tool='sumport'):
            data = [z, m['port'], m['severityCritical'], m['severityHigh'], m['severityMedium'], m['severityLow'], m['severityInfo']]
            port_list.append(data)

except Exception as e:
    print (e)

try:
    data1 = pandas.DataFrame(ip_data_list,columns=['IP','DNS','MAC','NetBios','Policy','Critical Issues','High Issues','Medium Issues','Low Issues','Info count'])
    data2 = pandas.DataFrame(vul_data_list,columns=['IP','Port','Protocol','DNS','CPE','Description','Synopsis','CVE','Severity','Version','Solution', 'Vul Publish Date', 'Patch Publish Date'])
    data3 = pandas.DataFrame(software_list,columns=['IP','Name','Active'])
    data4 = pandas.DataFrame(bulletines_list,columns=['IP','Bulletine ID','Severity'])
    data5 = pandas.DataFrame(services_list,columns=['IP','Service','Active'])
    data6 = pandas.DataFrame(port_list,columns=['IP','Port','Critical Issues','High Issues','Medium Issues','Low Issues','Info count'])
    with pandas.ExcelWriter('Nessus_Scan_'+str(scanid)+'.xlsx') as writer:
        data1.to_excel(writer, sheet_name='IP Data', index=False)
        data2.to_excel(writer, sheet_name='Vul Data', index=False)
        data3.to_excel(writer, sheet_name='Softwares', index=False)
        data4.to_excel(writer, sheet_name='Microsoft B', index=False)
        data5.to_excel(writer, sheet_name='Services', index=False)
        data6.to_excel(writer, sheet_name='Ports', index=False)
except:
    print ('Cannot Create the Excel File. Check the Permission')
 

sc.logout()
