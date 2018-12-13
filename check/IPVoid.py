import requests, csv, os
from bs4 import BeautifulSoup as bs

# ---------------------------------------------
#   PARENT CLASS FOR IPVOID REPUTATION CHECK
# ----------------------------------------------
class ipvoid:

    def error_status(self, error_code):
        error_dict = {400: 'BAD REQUEST', 401: 'UNAUTHORIZED', 403: 'ACCESS DENIED/FORBIDDEN', 404: 'NOT FOUND', 405:'METHOD NOT ALLOWED', 406: 'NO ACCEPTABLE TYPE SPECIFIED',
                      408: 'REQUEST TIME OUT', 415:'UNSUPPORTED MEDIA TYPE', 429: 'RATE LIMIT', 500: 'INTERNAL ERROR', 502: 'BAD GATEWAY', 503:'SERVICE UNAVAILABLE', 504:'GATEWAY TIMEOUT', 505:'HTTP VERSION NOT SUPPORTED'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING HTTP CALL TO IPVOID. ERROR CODE : '+str(error_code)

    def is_valid_ip(self, ip_add):
        ip = ip_add.strip()
        try:
            if (str(ip).split('.')[0] == '10') or (str(ip).split('.')[0] == '172' and str(ip).split('.')[1] in range(16, 31)) or (str(ip).split('.')[0] == '192' and str(ip).split('.')[1] == '168'):
                return False
            else:
                return True
        except:
            print('INVALID IPADDRESS')
            return False

# ---------------------------------------------------------------
#   IPCHECK INHERITED FORM IPVOID TO CHECK SCORE, COUNTRY, CITY
# ---------------------------------------------------------------
class IPCheck(ipvoid):

    def __init__(self, mode, ipvoid_url, ip=None, ipfile=None, ipbulk=None):
        self.mode = mode
        self.http_url = ipvoid_url
        if ip != None:
            self.ip = ip
        if ipfile != None:
            self.ipfile = ipfile
        if ipbulk != None:
            self.ipbulk = ipbulk

    def check_ip(self):
        if self.mode == 'Single':
            if self.is_valid_ip(self.ip):
                try:
                    formdata = {'ip': self.ip}
                    response = requests.post(self.http_url, formdata)
                    if response.status_code == 201 or response.status_code == 200:
                        soap = bs(response.content, 'html.parser')
                        table = soap.find('table')
                        tds, ip = score = country = city = [], ''
                        for row in table.findAll('tr'):
                            for col in row.findAll('td'):
                                tds.append(col.text.strip())
                        try:
                            ip = tds[7].replace('Find Sites | IP Whois', '')
                        except:
                            ip = 'No Info'
                        try:
                            if str(tds[5]).__contains__('POSSIBLY'):
                                score = tds[5].replace('POSSIBLY SAFE', '').strip().split('/')[0]
                            else:
                                score = tds[5].replace('BLACKLISTED', '').strip().split('/')[0]
                        except:
                            score = 'No Info'
                        try:
                            country = tds[19]
                        except:
                            country = 'No Info'
                        try:
                            city = tds[23]
                        except:
                            city = 'No Info'
                        return ip, score, country, city
                    else:
                        print('ERROR IN IPVOID CONNECTION : '+self.error_status(response.status_code))
                        return 'No Info', 'No Info', 'No Info', 'No Info'
                except requests.exceptions.ConnectionError:
                    print('UNABLE TO CONNECT IPVOID')
            else:
                ip = score = country = city = 'No Info'
                return ip, score, country, city

        elif self.mode == 'bulk':
            ipv_dict = {}
            for ipadd in self.ipbulk:
                try:
                    formdata = {'ip': ipadd}
                    response = requests.post(self.http_url, formdata)
                    if response.status_code == 201 or response.status_code == 200:
                        soap = bs(response.content, 'html.parser')
                        table = soap.find('table')
                        tds, ip = score = country = city = [], ''
                        for row in table.findAll('tr'):
                            for col in row.findAll('td'):
                                tds.append(col.text.strip())
                        try:
                            ip = tds[7].replace('Find Sites | IP Whois', '')
                        except:
                            ip = 'No Info'
                        try:
                            if str(tds[5]).__contains__('POSSIBLY'):
                                score = tds[5].replace('POSSIBLY SAFE', '').strip().split('/')[0]
                            else:
                                score = tds[5].replace('BLACKLISTED', '').strip().split('/')[0]
                        except:
                            score = 'No Info'
                        try:
                            country = tds[19]
                        except:
                            country = 'No Info'
                        try:
                            city = tds[23]
                        except:
                            city = 'No Info'
                        ipv_dict[ipadd] = [score, country, city]
                    else:
                        print('ERROR IN IPVOID CONNECTION : ' + self.error_status(response.status_code))
                        ipv_dict[ipadd] = ['No Info', 'No Info', 'No Info']
                except requests.exceptions.ConnectionError:
                    ipv_dict[ipadd] = ['No Info', 'No Info', 'No Info']
            return ipv_dict
