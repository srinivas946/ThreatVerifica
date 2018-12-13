import base64, requests, csv, os

# ---------------------------------------------------------------------
#   PARENT CLASS FOR IP_CHECK, DOMAIN_CHECK, URL_CHECK AND HASH_CHECK
# ---------------------------------------------------------------------
class ibm:
    def __init__(self, API_KEY, API_PASSWORD):
        self.API_KEY = API_KEY
        self.API_PASSWORD = API_PASSWORD

    def encode_authorization(self):
        pass_data = self.API_KEY+':'+self.API_PASSWORD
        data = base64.b64encode(pass_data.encode())
        return str(data.decode('utf-8'))

    def headers(self):
        header = {"Authorization": "Basic "+self.encode_authorization(), "Content-Type":"application/json"}
        return header

    def error_status(self, error_code):
        error_dict = {400: 'INVALID API KEY FORMAT', 401: 'UNAUTHORIZED', 402: 'YOUR MONTHLY QUOTA EXCEEDED',
                      403: 'ACCESS DENIED', 404: 'API KEY NOT FOUND', 406: 'NO ACCEPTABLE TYPE SPECIFIED',
                      429: 'RATE LIMIT', 500: 'INTERNAL ERROR'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING API CALL TO IBM X FORCE. ERROR CODE : '+str(error_code)

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


# ------------------------------------------------
#   IP REPUTATION CHECK INHERITED FROM IBM CLASS
#  -----------------------------------------------
class IPCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, ip=None, ipfile=None, ipbulk=None):
        ibm.__init__(self, API_KEY=API_KEY, API_PASSWORD=API_PASSWORD)
        self.mode = mode
        self.api = api
        if ip != None:
            self.ip = ip
        if ipfile != None:
            self.ipfile = ipfile
        if ipbulk != None:
            self.ipbulk = ipbulk

    def check_ip(self):
        if self.mode == 'Single':
            try:
                ip = score = country, category = '', []
                if self.is_valid_ip(self.ip):
                    response = requests.get(self.api+self.ip, headers = self.headers())
                    if response.status_code == 200:
                        json_response = response.json()
                        try:
                            ip = json_response['ip']
                        except:
                            ip = 'No Info'
                        try:
                            score = float(json_response['score'])
                        except:
                            score = 0
                        try:
                            country = json_response['history'][0]['geo']['country']
                        except:
                            country = 'No Info'
                        try:
                            category_data = json_response['categoryDescriptions']
                            if len(category_data)  != 0:
                                cat_list = ['Spam', 'Scanning IPs', 'Dynamic IPs', 'Anonymous']
                                for cat in cat_list:
                                    try:
                                        json_response['categoryDescriptions'][cat]
                                        category.append(cat)
                                    except:
                                        pass
                            else:
                                category.append('Unsuspicious')
                        except:
                            category.append('No Info')
                    else:
                        print('ERROR IN IBM X FORCE : '+self.error_status(response.status_code))
                        ip, score, country, category = self.ip, 0, 'No Info', 'No Info'

                    return ip, score, country, category

                else:
                    print('PRIVATE IP ADDRESS')
                    ip, score, country, category = self.ip, 0, 'No Info', 'No Info'

            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')
            except requests.exceptions.ConnectTimeout:
                print('UNABLE TO CONNECT TO IBM X FORCE')

        elif self.mode == 'bulk':
            ibm_dict = {}
            for ip in self.ipbulk:
                ipadd = score = country, category = '', []
                try:
                    if self.is_valid_ip(ip):
                        response = requests.get(self.api + ip, headers=self.headers())
                        if response.status_code == 200:
                            json_response = response.json()
                            try:
                                ipadd = json_response['ip']
                            except:
                                ipadd = 'No Info'
                            try:
                                score = float(json_response['score'])
                            except:
                                score = 0
                            try:
                                country = json_response['history'][0]['geo']['country']
                            except:
                                country = 'No Info'
                            try:
                                category_data = json_response['categoryDescriptions']
                                if len(category_data) != 0:
                                    cat_list = ['Spam', 'Scanning IPs', 'Dynamic IPs', 'Anonymous']
                                    for cat in cat_list:
                                        try:
                                            json_response['categoryDescriptions'][cat]
                                            category.append(cat)
                                        except:
                                            pass
                                else:
                                    category.append('Unsuspicious')
                            except:
                                category.append('No Info')
                        else:
                            print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                            score, country, category = 0, 'No Info', 'No Info'
                        ibm_dict[ip] = [score, country, category]
                    else:
                        ip, score, country, category = self.ip, 0, 'No Info', 'No Info'
                        ibm_dict[ip] = ['PRIVATE IP', 'PRIVATE IP', 'PRIVATE IP']

                except requests.exceptions.ConnectionError:
                    print('CHECK YOUR INTERNET CONNECTION')
            return ibm_dict



# -----------------------------------------------------
#   DOMAIN REPUTATION CHECK INHERITED FROM IBM CLASS
# -----------------------------------------------------
class DomainCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, domain=None, domainfile=None, domainbulk=None):
        ibm.__init__(self, API_KEY, API_PASSWORD)
        self.mode = mode
        self.api = api
        if domain != None:
            self.domain = domain
        if domainfile != None:
            self.domainfile = domainfile
        if domainbulk != None:
            self.domainbulk = domainbulk

    def check_domain(self):
        if self.mode == 'Single':
            try:
                domain = score = country, category = '', []
                response = requests.get(self.api + self.domain, headers=self.headers())
                if response.status_code == 200:
                    json_response = response.json()
                    try:
                        domain = json_response['result']['url']
                    except:
                        domain = 'No Info'
                    try:
                        score = float(json_response['result']['score'])
                    except:
                        score = 0
                    try:
                        country = json_response['history'][0]['geo']['country']
                    except:
                        country = 'No Info'
                    try:
                        category_data = json_response['result']['cats']
                        if len(category_data) != 0:
                            category.append(str(list(category_data.keys()).replace('[', '').replace(']', '')))
                        else:
                            category.append('Unsuspicious')
                    except:
                        category.append('No Info')
                    return domain, score, country, category
                else:
                    print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                    domain, score, country, category = self.domain, 'No Info', 'No Info', 'No Info'
                    return domain, score, country, category
            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'bulk':
           ibm_dict = {}
           for dom in self.domainbulk:
               try:
                   domain = score = country, category = '', []
                   response = requests.get(self.api + dom, headers=self.headers())
                   if response.status_code == 200:
                       json_response = response.json()
                       try:
                           domain = json_response['result']['url']
                       except:
                           domain = 'No Info'
                       try:
                           score = float(json_response['result']['score'])
                       except:
                           score = 0
                       try:
                           country = json_response['history'][0]['geo']['country']
                       except:
                           country = 'No Info'
                       try:
                           category_data = json_response['result']['cats']
                           if len(category_data) != 0:
                               category.append(str(list(category_data.keys()).replace('[', '').replace(']', '')))
                           else:
                               category.append('Unsuspicious')
                       except:
                           category.append('No Info')
                       ibm_dict[dom] = [score, country, category]
                   else:
                       print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                       domain, score, country, category = domain, 'No Info', 'No Info', 'No Info'
                       ibm_dict[dom] = [score, country, category]
               except requests.exceptions.ConnectionError:
                   domain, score, country, category = domain, 'No Info', 'No Info', 'No Info'
                   ibm_dict[domain] = [score, country, category]
           return ibm_dict

# --------------------------------------------
#   URL STATUS CHECK INHERITED FROM IBM CLASS
# --------------------------------------------
class UrlCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, url=None, urlfile=None, urlbulk=None):
        ibm.__init__(self, API_KEY, API_PASSWORD)
        self.api = api
        self.mode = mode
        if url != None:
            self.url = url
        if urlfile != None:
            self.urlfile = urlfile
        if urlbulk != None:
            self.urlbulk = urlbulk

    def check_url(self):
        if self.mode == 'Single':
            try:
                url = score = country, category = '', []
                response = requests.get(self.api + self.url, headers=self.headers())
                if response.status_code == 200:
                    json_response = response.json()
                    try:
                        url = json_response['result']['url']
                    except:
                        url = 'No Info'
                    try:
                        score = float(json_response['result']['score'])
                    except:
                        score = 0
                    try:
                        country = json_response['history'][0]['geo']['country']
                    except:
                        country = 'No Info'
                    try:
                        category_data = json_response['result']['cats']
                        if len(category_data) != 0:
                            category.append(str(list(category_data.keys()).replace('[', '').replace(']', '')))
                        else:
                            category.append('Unsuspicious')
                    except:
                        category.append('No Info')
                else:
                    print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                    url, score, country, category = self.url, 'No Info', 'No Info', 'No Info'
                return url, score, country, category
            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'bulk':
            ibm_dict = {}
            for url_data in self.urlbulk:
                try:
                    url = score = country, category = '', []
                    response = requests.get(self.api + url_data, headers=self.headers())
                    if response.status_code == 200:
                        json_response = response.json()
                        try:
                            url = json_response['result']['url']
                        except:
                            url = 'No Info'
                        try:
                            score = float(json_response['result']['score'])
                        except:
                            score = 0
                        try:
                            country = json_response['history'][0]['geo']['country']
                        except:
                            country = 'No Info'
                        try:
                            category_data = json_response['result']['cats']
                            if len(category_data) != 0:
                                category.append(str(list(category_data.keys()).replace('[', '').replace(']', '')))
                            else:
                                category.append('Unsuspicious')
                        except:
                            category.append('No Info')

                    else:
                        print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                        url, score, country, category = url, 'No Info', 'No Info', 'No Info'
                    ibm_dict[url_data] = score, country, category
                except requests.exceptions.ConnectionError:
                    url, score, country, category = url, 'No Info', 'No Info', 'No Info'
                    ibm_dict[url_data] = score, country, category
            return ibm_dict


# ---------------------------------------------
#   HASH VALUE CHECK INHERITED FROM IBM CLASS
# ---------------------------------------------
class HashCheck(ibm):
    def __init__(self, API_KEY, API_PASSWORD, api, mode, hash=None, hashfile=None, hashbulk=None):
        ibm.__init__(self, API_KEY, API_PASSWORD)
        self.mode = mode
        self.api = api
        if hash != None:
            self.hash = hash
        if hashfile != None:
            self.hashfile = hashfile
        if hashbulk != None:
            self.hashbulk = hashbulk

    def check_hash(self):
        if self.mode == 'Single':
            try:
                family, type, risk = [], '', ''
                response = requests.get(self.api + self.hash, headers=self.headers())
                if response.status_code == 200:
                    json_response = response.json()
                    try:
                        family.append(str(json_response['malware']['origins']['external']['family']).replace('[', '').replace(']', ''))
                    except:
                        family.append('No Info')
                    try:
                        type = json_response['malware']['type']
                    except:
                        type = 'No Info'
                    try:
                        risk = json_response['malware']['risk']
                    except:
                        risk = 'No Info'
                else:
                    print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                    family, type = risk = ['No Info'], 'No Info'

                return self.hash, family, type, risk

            except requests.exceptions.ConnectionError:
                print('CHECK YOUR INTERNET CONNECTION')

        elif self.mode == 'bulk':
            ibm_dict = {}
            for hash in self.hashbulk:
                try:
                    family, type, risk = [], '', ''
                    response = requests.get(self.api + hash, headers=self.headers())
                    if response.status_code == 200:
                        json_response = response.json()
                        try:
                            family.append(str(json_response['malware']['origins']['external']['family']).replace('[', '').replace(']', ''))
                        except:
                            family.append('No Info')
                        try:
                            type = json_response['malware']['type']
                        except:
                            type = 'No Info'
                        try:
                            risk = json_response['malware']['risk']
                        except:
                            risk = 'No Info'
                    else:
                        print('ERROR IN IBM X FORCE : ' + self.error_status(response.status_code))
                        family, type = risk = ['No Info'], 'No Info'

                    ibm_dict[hash] = family, type, risk

                except requests.exceptions.ConnectionError:
                    family, type = risk = ['No Info'], 'No Info'
                    ibm_dict[hash] = family, type, risk
            return ibm_dict

