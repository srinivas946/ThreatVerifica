import csv, os, requests

# -----------------------------------------------------------
#   PARENT CLASS FOR URL CHECK , FILE SCAN , AND HASH CHECK
# -----------------------------------------------------------
class VirusTotal:
    def __init__(self, API_KEY):
        self.API_KEY = API_KEY

    def error_status(self, error_code):
        error_dict = {204:'LIMIT EXCEEDED', 403:'FORBIDDEN ERROR'}
        try:
            return error_dict[error_code]
        except:
            return 'ERROR IN MAKING HTTP CALL TO VIRUS TOTAL. ERROR CODE : '+str(error_code)

# ---------------------------------------------
#   CHILD CLASS: SINGLE OR MULTIPLE URL CHECKS
# ---------------------------------------------
class UrlCheck(VirusTotal):

    def __init__(self, API_KEY, api, mode, url=None, urllist=None):
        VirusTotal.__init__(self, API_KEY)
        self.api = api
        self.mode = mode
        if url != None:
            self.url = url
        if urllist != None:
            self.urllist = urllist

    def check_url(self):
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        if self.mode == 'Single':
            url, scan_id, score, blacklist_by, permalink = '', '', '', [], ''
            params = {'apikey': self.API_KEY, 'resource': self.url}
            try:
                response = requests.post(self.api, params=params, headers=headers)
                if response.status_code != 204:
                    try:
                        json_response = response.json()
                        while(True):
                            if json_response['response_code'] != -2:
                                try:
                                    url = self.url
                                except:
                                    url = 'No Info'
                                try:
                                    score = str(json_response['positives'])+'/'+str(json_response['total'])
                                except:
                                    score = 'No Info'
                                try:
                                    scan_id = json_response['scan_id']
                                except:
                                    scan_id = 'No Info'
                                try:
                                    for data in json_response['scans']:
                                        if json_response['scans'][data]['detected'] == True:
                                            blacklist_by.append(data)
                                except:
                                    blacklist_by = []
                                try:
                                    permalink = json_response['permalink']
                                except:
                                    permalink = 'No Info'
                                break
                    except:
                        url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                elif response.status_code == 204:
                    url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                else:
                    url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                return url, scan_id, score, blacklist_by, permalink

            except requests.exceptions.ConnectionError:
                url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
            return url, scan_id, score, blacklist_by, permalink

        elif self.mode == 'bulk':
            url_context = []
            for url_data in self.urllist:
                url, scan_id, score, blacklist_by, permalink = '', '', '', [], ''
                params = {'apikey': self.API_KEY, 'resource': url_data}
                try:
                    response = requests.post(self.api, params=params, headers=headers)
                    if response.status_code != 204:
                        try:
                            json_response = response.json()
                            while (True):
                                if json_response['response_code'] != -2:
                                    try:
                                        url = self.url
                                    except:
                                        url = 'No Info'
                                    try:
                                        score = str(json_response['positives']) + '/' + str(json_response['total'])
                                    except:
                                        score = 'No Info'
                                    try:
                                        scan_id = json_response['scan_id']
                                    except:
                                        scan_id = 'No Info'
                                    try:
                                        for data in json_response['scans']:
                                            if json_response['scans'][data]['detected'] == True:
                                                blacklist_by.append(data)
                                    except:
                                        blacklist_by = []
                                    try:
                                        permalink = json_response['permalink']
                                    except:
                                        permalink = 'No Info'
                                    break
                        except:
                            url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                    elif response.status_code == 204:
                        url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                    else:
                        url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                    url_context[url] = [scan_id, score, blacklist_by, permalink]

                except requests.exceptions.ConnectionError:
                    url, scan_id, score, blacklist_by, permalink = 'No Info', 'No Info', 'No Info', [], ''
                url_context[self.url] = [scan_id, score, blacklist_by, permalink]
            return url_context



# ----------------------------------------------
#   CHILD CLASS: HASH CHECK SINGLE AND MUTIPLES
# ----------------------------------------------
class HashCheck(VirusTotal):

    def __init__(self, API_KEY, api, mode, hash=None, hash_list=None):
        VirusTotal.__init__(self, API_KEY)
        self.api = api
        self.mode = mode
        if hash != None:
            self.hash = hash
        if hash_list != None:
            self.hash_list = hash_list

    def check_hash(self):
        if self.mode == 'Single':
            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = '', '', '', '', '', '', []
            params = {'apikey': self.API_KEY, 'resource': self.hash}
            headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent": "gzip,  My Python requests library example client or username"
            }
            try:
                response = requests.get(self.api, params=params, headers=headers)
                if response.status_code != 204:
                    json_response = response.json()

                    try:
                        scan_id = json_response['scan_id']
                    except:
                        scan_id = 'No Info'
                    try:
                        score = str(json_response['positives'])+'/'+str(json_response['total'])
                    except:
                        score = 'No Info'
                    try:
                        md5 = json_response['md5']
                    except:
                        md5 = 'No Info'
                    try:
                        sha256 = json_response['sha256']
                    except:
                        sha256 = 'No Info'
                    try:
                        sha1 = json_response['sha1']
                    except:
                        sha1 = 'No Info'
                    try:
                        permalink = json_response['permalink']
                    except:
                        permalink = 'No Info'
                    try:
                        while (True):
                            if json_response['response_code'] != -2:
                                for data in json_response['scans']:
                                    if json_response['scans'][data]['detected'] == True:
                                        blacklisted_by.append(data)
                                break
                    except:
                        blacklisted_by = []

                elif response.status_code == 204:
                    scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                else:
                    scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                return self.hash, scan_id, score, md5, sha256, sha1, permalink, blacklisted_by

            except requests.exceptions.ConnectionError:
                print('NOT ABLE TO CONNECT TO VIRUSTOTAL')

        elif self.mode == 'bulk':
            hash_dict = {}
            for hashdata in self.hash_list:
                scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = '', '', '', '', '', '', []
                params = {'apikey': self.API_KEY, 'resource': hashdata}
                headers = {
                    "Accept-Encoding": "gzip, deflate",
                    "User-Agent": "gzip,  My Python requests library example client or username"
                }
                try:
                    response = requests.get(self.api, params=params, headers=headers)
                    if response.status_code != 204:
                        json_response = response.json()

                        try:
                            scan_id = json_response['scan_id']
                        except:
                            scan_id = 'No Info'
                        try:
                            score = str(json_response['positives']) + '/' + str(json_response['total'])
                        except:
                            score = 'No Info'
                        try:
                            md5 = json_response['md5']
                        except:
                            md5 = 'No Info'
                        try:
                            sha256 = json_response['sha256']
                        except:
                            sha256 = 'No Info'
                        try:
                            sha1 = json_response['sha1']
                        except:
                            sha1 = 'No Info'
                        try:
                            permalink = json_response['permalink']
                        except:
                            permalink = 'No Info'
                        try:
                            while (True):
                                if json_response['response_code'] != -2:
                                    for data in json_response['scans']:
                                        if json_response['scans'][data]['detected'] == True:
                                            blacklisted_by.append(data)
                                    break
                        except:
                            blacklisted_by = []

                    elif response.status_code == 204:
                        scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                    else:
                        scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                    hash_dict[hashdata] = [scan_id, score, md5, sha256, sha1, permalink, blacklisted_by]

                except requests.exceptions.ConnectionError:
                    scan_id, score, md5, sha256, sha1, permalink, blacklisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                hash_dict[hashdata] = [scan_id, score, md5, sha256, sha1, permalink, blacklisted_by]
            return hash_dict

# -----------------------------------------------------------
#   CHILD CLASS: FILE HASH SCAN SINLGE AND MULTIPLE FILES
# -----------------------------------------------------------
class FileHash(VirusTotal):

    def __init__(self, API_KEY, api_list, mode, singlefile=None):
        VirusTotal.__init__(self, API_KEY)
        self.api_list = api_list
        self.mode = mode
        if singlefile != None:
            self.singlefile = singlefile

    def scan_files(self):
        headers, filescan_dict = {"Accept-Encoding": "gzip, deflate", }, {}
        if self.mode == 'Single':
            scan_id, score, md5, sha256, sha1, permalink, blacklisted_by  = '', '', '', '', '', '', []
            files = {'file': (self.singlefile, open(self.singlefile, 'rb'))}
            params = {'apikey': self.API_KEY}
            try:
                response = requests.post(self.api_list[0], files=files, params=params)
                if response.status_code != 204:
                    json_response = response.json()
                    resource = json_response['resource']
                    params = {'apikey': self.API_KEY, 'resource': resource}
                    response = requests.get(self.api_list[1], params=params, headers=headers)
                    json_response = response.json()
                    try:
                        scan_id = json_response['scan_id']
                    except:
                        scan_id = 'No Info'
                    try:
                        score = str(json_response['positives'])+'/'+str(json_response['total'])
                    except:
                        score = 'No Info'
                    try:
                        md5 = json_response['md5']
                    except:
                        md5 = 'No Info'
                    try:
                        sha256 = json_response['sha256']
                    except:
                        sha256 = 'No Info'
                    try:
                        sha1 = json_response['sha1']
                    except:
                        sha1 = 'No Info'
                    try:
                        permalink = json_response['permalink']
                    except:
                        permalink = 'No Info'
                    try:
                        while (True):
                            if json_response['response_code'] != -2:
                                for data in json_response['scans']:
                                    if json_response['scans'][data]['detected'] == True:
                                        blacklisted_by.append(data)
                                break
                    except:
                        blacklisted_by = ['No Info']

                elif response.status_code == 204:
                    scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []
                else:
                    scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []

                return self.singlefile, scan_id, score, md5, sha256, sha1, permalink, blacklisted_by

            except requests.exceptions.ConnectionError:
                scan_id, score, md5, sha256, sha1, permalink, blaclisted_by = 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', 'No Info', []

            return self.singlefile, scan_id, score, md5, sha256, sha1, permalink, blacklisted_by
