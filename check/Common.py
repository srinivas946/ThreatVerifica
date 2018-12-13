from . import IBMX_Force, IPVoid, IPLocation, VirusTotal
from check.models import Ibm_API_Credits, Virus_Total_Credits

def ibmxforce(ibm_context, mode, selected_choice):
    ibm_api = Ibm_API_Credits.objects.get(pk=1)
    if mode == 'single':
        if is_valid_ip(selected_choice):
            ipcheck = IBMX_Force.IPCheck(API_KEY=ibm_api.api_key,
                                         API_PASSWORD=ibm_api.api_password,
                                         api='https://api.xforce.ibmcloud.com/ipr/',
                                         mode='Single', ip=selected_choice)
            ibm_ip, ibm_score, ibm_country, ibm_category = ipcheck.check_ip()
            ibm_context['IPADDRESS'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context[
                'CATEGORY'] = ibm_ip, ibm_score, ibm_country, ibm_category
            return ibm_context

        elif is_valid_domain(selected_choice):
            domaincheck = IBMX_Force.DomainCheck(API_KEY=ibm_api.api_key,
                                                 API_PASSWORD=ibm_api.api_password,
                                                 api='https://api.xforce.ibmcloud.com/url/', mode='Single',
                                                 domain=selected_choice)
            ibm_domain, ibm_score, ibm_country, ibm_category =domaincheck.check_domain()
            ibm_context['DOMAIN'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_domain, ibm_score, ibm_country, ibm_category
            return ibm_context

        elif is_valid_url(selected_choice):
            urlcheck = IBMX_Force.UrlCheck(API_KEY=ibm_api.api_key,
                                           API_PASSWORD=ibm_api.api_password,
                                           api='https://api.xforce.ibmcloud.com/url/', mode='Single',
                                           url=selected_choice)
            ibm_url, ibm_score, ibm_country, ibm_category = urlcheck.check_url()
            ibm_context['URL'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_url, ibm_score, ibm_country, ibm_category
            return ibm_context

        else:
            hash_check = IBMX_Force.HashCheck(API_KEY=ibm_api.api_key,
                                              API_PASSWORD=ibm_api.api_password,
                                              api='https://api.xforce.ibmcloud.com/malware/', mode='Single',
                                              hash=selected_choice)
            ibm_hash, ibm_family, ibm_type, ibm_risk = hash_check.check_hash()
            ibm_context['HASH'], ibm_context['FAMILY'], ibm_context['TYPE'], ibm_context['RISK'] = ibm_hash, ibm_family, ibm_type, ibm_risk
            return ibm_context

    elif mode == 'bulk':
        ipfind, domain_find, url_find = [], [], []
        for choice in selected_choice:
            if is_valid_ip(choice):
                ipfind.append(0)
            elif is_valid_domain(choice):
                domain_find.append(0)
            elif is_valid_url(choice):
                url_find.append(0)
        if len(ipfind) == len(selected_choice):
            ipcheck = IBMX_Force.IPCheck(API_KEY=ibm_api.api_key,
                                         API_PASSWORD=ibm_api.api_password,
                                         api='https://api.xforce.ibmcloud.com/ipr/',
                                         mode='bulk', ipbulk=selected_choice)
            ibm_context = ipcheck.check_ip()
            return ibm_context

        elif len(domain_find) == len(selected_choice):
            domaincheck = IBMX_Force.DomainCheck(API_KEY=ibm_api.api_key,
                                                 API_PASSWORD=ibm_api.api_password,
                                                 api='https://api.xforce.ibmcloud.com/url/', mode='bulk',
                                                 domainbulk=selected_choice)
            ibm_context = domaincheck.check_domain()
            return ibm_context

        elif len(url_find) == len(selected_choice):
            urlcheck = IBMX_Force.UrlCheck(API_KEY=ibm_api.api_key,
                                           API_PASSWORD=ibm_api.api_password,
                                           api='https://api.xforce.ibmcloud.com/url/', mode='bulk',
                                           urlbulk=selected_choice)
            ibm_context = urlcheck.check_url()
            return ibm_context

        else:
            hash_check = IBMX_Force.HashCheck(API_KEY=ibm_api.api_key,
                                              API_PASSWORD=ibm_api.api_password,
                                              api='https://api.xforce.ibmcloud.com/malware/', mode='bulk',
                                              hashbulk=selected_choice)
            ibm_context = hash_check.check_hash()
            return ibm_context


def ipvoid_data(ipv_context, mode, selected_choice):
    if mode == 'single':
        if is_valid_ip(selected_choice):
            ipch = IPVoid.IPCheck(mode='Single', ipvoid_url='http://www.ipvoid.com/ip-blacklist-check/', ip=selected_choice)
            ipv_ip, ipv_score, ipv_country, ipv_city = ipch.check_ip()
            ipv_context['IPADDRESS'], ipv_context['SCORE'], ipv_context['COUNTRY'], ipv_context[
                'CITY'] = ipv_ip, ipv_score, ipv_country, ipv_city
            return ipv_context
    elif mode == 'bulk':
        ip_find = []
        for choice in selected_choice:
            if is_valid_ip(choice):
                ip_find.append(0)
        if len(ip_find) == len(selected_choice):
            ipch = IPVoid.IPCheck(mode='bulk', ipvoid_url='http://www.ipvoid.com/ip-blacklist-check/',
                                  ipbulk=selected_choice)
            ipv_context = ipch.check_ip()
            return ipv_context


def virustotal_data(vt_context, mode, selected_choice):
    vc = Virus_Total_Credits.objects.get(pk=1)
    if mode == 'single':
        if is_valid_url(selected_choice):
            tc = VirusTotal.UrlCheck(mode='Single', api='https://www.virustotal.com/vtapi/v2/url/report', url=selected_choice, API_KEY=vc.apikey)
            vt_url, vt_scan_id, vt_score, vt_blacklist, vt_link = tc.check_url()
            vt_context['URL'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['LINK'], vt_context['BLACKLIST'] = vt_url, vt_scan_id, vt_score, vt_blacklist, vt_link
            return vt_context
        elif is_valid_domain(selected_choice):
            pass
        elif is_valid_ip(selected_choice):
            pass
        else:
            try:
                tc = VirusTotal.HashCheck(mode='Single', api='https://www.virustotal.com/vtapi/v2/file/report', hash=selected_choice, API_KEY=vc.apikey)
                vt_hash, vt_scan_id, vt_score, vt_md5, vt_sha256, vt_sha1, vt_blacklist, vt_link = tc.check_hash()
                vt_context['HASH'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['MD5'], vt_context['SHA256'], vt_context['SHA1'], vt_context['LINK'], vt_context['BLACKLIST'] = vt_hash, vt_scan_id, vt_score, vt_md5, vt_sha256, vt_sha1, vt_blacklist, vt_link
                return vt_context
            except:
                pass
    elif mode == 'file':
        tc = VirusTotal.FileHash(mode='Single', api_list=['https://www.virustotal.com/vtapi/v2/file/scan', 'https://www.virustotal.com/vtapi/v2/file/report'], API_KEY=vc.apikey, singlefile=selected_choice)
        file, scan_id, score, md5, sha256, sha1, link, blacklist = tc.scan_files()
        vt_context['FILE'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['MD5'], vt_context['SHA256'], vt_context['SHA1'], vt_context['LINK'], vt_context['BLACKLIST'] = file, scan_id, score, md5, sha256, sha1, link, blacklist
        return vt_context

def iploc(loc_context, mode, selected_choice):
    if mode == 'single':
        if is_valid_ip(selected_choice):
            lc = IPLocation.LocationCheck(http_url='https://www.iplocation.net/', mode='Single',
                                          ip=selected_choice)
            loc_ip, loc_country, loc_city, loc_region, loc_isp, loc_lat, loc_lon = lc.check_location()
            loc_context['IPADDRESS'], loc_context['COUNTRY'], loc_context['CITY'], loc_context['REGION'], loc_context['ISP'], \
            loc_context['LATITUDE'], loc_context[
                'LONGITUDE'] = loc_ip, loc_country, loc_city, loc_region, loc_isp, loc_lat, loc_lon
            return loc_context

def is_valid_ip(ipadd):
    ip = ipadd.strip()
    try:
        if int(ip.split('.')[0]) == 10 or (int(ip.split('.')[0]) == 172 and int(ip.split('.')[1]) in range(16, 32)) or (int(ip.split('.')[0]) == 192 and int(ip.split('.')[1]) == 168 and int(ip.split('.')[2]) in range(0, 255)):
            return False
        else:
            return True
    except:
        return False


def is_valid_domain(domain):
    dom = domain.strip()
    li = ['com', 'in', 'net', 'gr', 'co', 'app', 'online', 'space', 'store', 'tech', 'org', 'club', 'design',
          'shop', 'iste', 'io', 'me', 'us', 'ca', 'ac', 'academy', 'accountant', 'actor', 'adult', 'ae.org', 'ae',
          'af', 'africa', 'ag', 'agency', 'ai', 'am', 'apartments', 'com.ar', 'archi', 'art', 'as', 'asia',
          'associates', 'at', 'attorney', 'com.au', 'id.au', 'net.au', 'au', 'ru','org.au', 'auction']
    try:
        if dom.split('.')[-1] in li:
            return True
        elif dom.split('.')[-2] in li:
            return True
        else:
            return False
    except:
        return False

def is_valid_url(url):
    ur = url.strip()
    if ur.__contains__('http') or ur.__contains__('https') or ur.__contains__('www'):
        return True
    else:
        return False
