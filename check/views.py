from django.shortcuts import render
from .Common import ibmxforce, ipvoid_data, iploc, virustotal_data, is_valid_ip,is_valid_domain, is_valid_url
from check.models import Ipvoid_Ip, Ibm_Ip,IPLocation, Ibm_domain, Ibm_Url, Ibm_Hash, Virus_Total_Url, Virus_Total_Hash, Ibm_API_Credits, Virus_Total_Credits
from django.core.files.storage import FileSystemStorage
import csv, os

# =======================
#   INDEX PAGE VIEW
# ========================
def index(request):
    return render(request, 'check/index.html')

# ======================
#   DETAIL PAGE VIEW
# ======================
def detail(request):
    selected_choice = request.POST.get('q')
    if '5' in request.POST.getlist('checks[]'):
        checkbox = ['1', '2', '3', '4']
    else:
        checkbox = request.POST.getlist('checks[]')
    ibm_context, ipv_context, vt_context, loc_context = {}, {}, {}, {}
    # ---------------------------
    #   IBM X FORCE
    # --------------------------
    if '1' in checkbox:
        val = selected_choice.strip()
        if is_valid_ip(val):
            try:
                ibm_db = Ibm_Ip.objects.get(ipadd=val)
                ibm_context['IPADDRESS'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.ipadd, ibm_db.score, ibm_db.country, ibm_db.category
            except Ibm_Ip.DoesNotExist:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_Ip(ipadd=ibm_context['IPADDRESS'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                ibm.save()
        elif is_valid_domain(val):
            try:
                ibm_db = Ibm_domain.objects.get(domain=val)
                ibm_context['DOMAIN'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.domain, ibm_db.score, ibm_db.country, ibm_db.category
            except:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_domain(domain=ibm_context['DOMAIN'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'],category=ibm_context['CATEGORY'])
                ibm.save()
        elif is_valid_url(val):
            try:
                ibm_db = Ibm_Url.objects.get(url=val)
                ibm_context['URL'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.url, ibm_db.score, ibm_db.country, ibm_db.category
            except:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_Url(url=ibm_context['URL'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                ibm.save()
        else:
            try:
                ibm_db = Ibm_Hash.objects.get(hash=val)
                ibm_context['HASH'], ibm_context['FAMILY'], ibm_context['TYPE'], ibm_context['RISK'] = ibm_db.hash, ibm_db.family, ibm_db.type, ibm_db.risk
            except Ibm_Hash.DoesNotExist:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_Hash(hash=ibm_context['HASH'], family=ibm_context['FAMILY'], type=ibm_context['TYPE'],risk=ibm_context['RISK'])
                ibm.save()
            except:
                return render(request, 'check/Service_Unavailable.html', {'data':'IBM X Force'})

    # -------------------------
    #   IPVOID SECTION
    # -------------------------
    if '2' in checkbox:
        val = selected_choice.strip()
        if is_valid_ip(val):
            try:
                ipv_db = Ipvoid_Ip.objects.get(ipadd=val)
                ipv_context['IPADDRESS'], ipv_context['SCORE'], ipv_context['COUNTRY'], ipv_context[
                    'CITY'] = ipv_db.ipadd, ipv_db.score, ipv_db.country, ipv_db.city
            except Ipvoid_Ip.DoesNotExist:
                ipv_context = ipvoid_data(ipv_context=ipv_context, mode="single", selected_choice=val)
                ipv = Ipvoid_Ip(ipadd=val, score=ipv_context['SCORE'], country=ipv_context['COUNTRY'],city=ipv_context['CITY'])
                ipv.save()
            except:
                return render(request, 'check/Service_Unavailable.html', {'data':'IPVoid'})

    # --------------------------
    #   IPLOCATION SECTION
    # --------------------------
    if '3' in checkbox:
        val = selected_choice.strip()
        try:
            loc_db = IPLocation.objects.get(ipadd=val)
            loc_context['IPADDRESS'], loc_context['COUNTRY'], loc_context['CITY'], loc_context['REGION'], loc_context[
                'ISP'], loc_context['LATITUDE'], loc_context[
                'LONGITUDE'] = loc_db.ipadd, loc_db.country, loc_db.city, loc_db.region, loc_db.isp, loc_db.lat, loc_db.lon
        except IPLocation.DoesNotExist:
            loc_context = iploc(loc_context=loc_context, mode='single', selected_choice=selected_choice)
            ip_loc = IPLocation(ipadd=loc_context['IPADDRESS'], country=loc_context['COUNTRY'],
                                city=loc_context['CITY'], region=loc_context['REGION'], isp=loc_context['ISP'],
                                lat=loc_context['LATITUDE'], lon=loc_context['LONGITUDE'])
            ip_loc.save()

    # ---------------------
    # VIRUS TOTAL SECTION
    # ---------------------
    if '4' in checkbox:
        val = selected_choice.strip()
        if is_valid_url(val):
            try:
                vt_db = Virus_Total_Url.objects.get(url=val)
                vt_context['URL'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['BLACKLIST'], vt_context['LINk'] = vt_db.url, vt_db.scan_id, vt_db.score, vt_db.blacklist, vt_db.link
            except Virus_Total_Url.DoesNotExist:
                vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                vtotal_db = Virus_Total_Url(url=vt_context['URL'], scan_id=vt_context['SCAN_ID'], score=vt_context['SCORE'], blacklist=vt_context['BLACKLIST'], link=vt_context['LINK'])
                vtotal_db.save()
        else:
            try:
                vt_db = Virus_Total_Hash.objects.get(hash=val)
                vt_context['HASH'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['MD5'], vt_context['SHA256'], vt_context['SHA1'], vt_context['LINK'], vt_context['BLACKLIST'] = vt_db.hash, vt_db.scan_id, vt_db.score, vt_db.md5, vt_db.sha256, vt_db.sha1, vt_db.link, vt_db.blacklist
            except Virus_Total_Hash.DoesNotExist:
                try:
                    vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                    vtotal_db = Virus_Total_Hash(hash=vt_context['HASH'], scan_id=vt_context['SCAN_ID'],score=vt_context['SCORE'], md5=vt_context['MD5'], sha256=vt_context['SHA256'], sha1=vt_context['SHA1'], blacklist=vt_context['BLACKLIST'], link=vt_context['LINK'])
                    vtotal_db.save()
                except:
                    pass

    context = {
        'check':checkbox,
        'ibm':ibm_context,
        'ipv':ipv_context,
        'iploc':loc_context,
        'virustotal':vt_context,
    }
    return render(request, 'check/detail.html', {'reputation':context})



# ===========================
#   IBM X FORCE (check/ibm/)
# ===========================
def ibm(request):
    single = request.POST.get('Singledata')
    bulk = request.POST.get('bulk[]')
    ibm_context, context = {}, {}
    # ---------------------------------------------------
    #   SINGLE DATA CHECK (IPADDRESS, DOMAIN, HASH, URL)
    # ---------------------------------------------------
    if single != None:
        val = single.strip()
        if is_valid_ip(val):
            try:
                ibm_db = Ibm_Ip.objects.get(ipadd=val)
                ibm_context['IPADDRESS'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.ipadd, ibm_db.score, ibm_db.country, ibm_db.category
            except Ibm_Ip.DoesNotExist:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_Ip(ipadd=ibm_context['IPADDRESS'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                ibm.save()
        elif is_valid_domain(val):
            try:
                ibm_db = Ibm_domain.objects.get(domain=val)
                ibm_context['DOMAIN'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.domain, ibm_db.score, ibm_db.country, ibm_db.category
            except:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_domain(domain=ibm_context['DOMAIN'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'],category=ibm_context['CATEGORY'])
                ibm.save()
        elif is_valid_url(val):
            try:
                ibm_db = Ibm_Url.objects.get(url=val)
                ibm_context['URL'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.url, ibm_db.score, ibm_db.country, ibm_db.category
            except:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_Url(url=ibm_context['URL'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                ibm.save()
        else:
            try:
                ibm_db = Ibm_Hash.objects.get(hash=val)
                ibm_context['HASH'], ibm_context['FAMILY'], ibm_context['TYPE'], ibm_context['RISK'] = ibm_db.hash, ibm_db.family, ibm_db.type, ibm_db.risk
            except Ibm_Hash.DoesNotExist:
                ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                ibm = Ibm_Hash(hash=ibm_context['HASH'], family=ibm_context['FAMILY'], type=ibm_context['TYPE'],risk=ibm_context['RISK'])
                ibm.save()

        context = {
            'ibm_data': ibm_context
        }
    # ---------------------------------------------
    #   BULK CHECK (IPADDRESS, DOMAIN, HASH, URL)
    # ---------------------------------------------
    elif bulk != None:
        bulk_list, ibm_data, = [], {}
        for data in str(bulk).split(','):
            val = data.strip()
            if is_valid_ip(val):
                ibm_context = {}
                try:
                    ibm_db = Ibm_Ip.objects.get(ipadd=val)
                    ibm_context['IPADDRESS'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.ipadd, ibm_db.score, ibm_db.country, ibm_db.category
                except Ibm_Ip.DoesNotExist:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_Ip(ipadd=ibm_context['IPADDRESS'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                    ibm.save()
                ibm_data[val] = ibm_context
                del ibm_context
            elif is_valid_domain(val):
                ibm_context = {}
                try:
                    ibm_db = Ibm_domain.objects.get(domain=val)
                    ibm_context['DOMAIN'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context[
                        'CATEGORY'] = ibm_db.domain, ibm_db.score, ibm_db.country, ibm_db.category
                except:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_domain(domain=ibm_context['DOMAIN'], score=ibm_context['SCORE'],
                                     country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                    ibm.save()
                ibm_data[val] = ibm_context
                del ibm_context
            elif is_valid_url(val):
                ibm_context = {}
                try:
                    ibm_db = Ibm_Url.objects.get(url=val)
                    ibm_context['URL'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context[
                        'CATEGORY'] = ibm_db.url, ibm_db.score, ibm_db.country, ibm_db.category
                except:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_Url(url=ibm_context['URL'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'],
                                  category=ibm_context['CATEGORY'])
                    ibm.save()
                ibm_data[val] = ibm_context
                del ibm_context
            else:
                ibm_context = {}
                try:
                    ibm_db = Ibm_Hash.objects.get(hash=val)
                    ibm_context['HASH'], ibm_context['FAMILY'], ibm_context['TYPE'], ibm_context[
                        'RISK'] = ibm_db.hash, ibm_db.family, ibm_db.type, ibm_db.risk
                except Ibm_Hash.DoesNotExist:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_Hash(hash=ibm_context['HASH'], family=ibm_context['FAMILY'], type=ibm_context['TYPE'],
                                   risk=ibm_context['RISK'])
                    ibm.save()
                ibm_data[val] = ibm_context
                del ibm_context
        context = {
            'ibm_bulk': ibm_data
        }

    # --------------------------------------------------------
    #   UPLOAD FILE TO CHECK (IPADDRESS, DOMAIN, HASH, URL)
    # --------------------------------------------------------
    elif request.POST and request.FILES['myfile']:
        file_list, val_list, mydict = [], [], []
        file = request.FILES['myfile']
        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        uploaded_file_url = fs.url(filename)
        file_name = os.getcwd().replace("\\", '/')+uploaded_file_url
        with open(file_name, 'r') as csvfile:
            csvread = csv.reader(csvfile)
            for row in csvread:
                if row[0] not in [None, '', 'none', '-']:
                    file_list.append(row[0])
                elif row[1] not in [None, '', 'none', '-']:
                    file_list.append(row[1])
        for data in file_list:
            val = data.strip()
            if is_valid_ip(val):
                ibm_context = {}
                try:
                    ibm_db = Ibm_Ip.objects.get(ipadd=val)
                    ibm_context['IPADDRESS'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context['CATEGORY'] = ibm_db.ipadd, ibm_db.score, ibm_db.country, ibm_db.category
                except Ibm_Ip.DoesNotExist:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_Ip(ipadd=ibm_context['IPADDRESS'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                    ibm.save()
                val_list.append(ibm_context)
                del ibm_context
            elif is_valid_domain(val):
                ibm_context = {}
                try:
                    ibm_db = Ibm_domain.objects.get(domain=val)
                    ibm_context['DOMAIN'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context[
                        'CATEGORY'] = ibm_db.domain, ibm_db.score, ibm_db.country, ibm_db.category
                except:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_domain(domain=ibm_context['DOMAIN'], score=ibm_context['SCORE'],
                                     country=ibm_context['COUNTRY'], category=ibm_context['CATEGORY'])
                    ibm.save()
                val_list.append(ibm_context)
                del ibm_context
            elif is_valid_url(val):
                ibm_context = {}
                try:
                    ibm_db = Ibm_Url.objects.get(url=val)
                    ibm_context['URL'], ibm_context['SCORE'], ibm_context['COUNTRY'], ibm_context[
                        'CATEGORY'] = ibm_db.url, ibm_db.score, ibm_db.country, ibm_db.category
                except:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_Url(url=ibm_context['URL'], score=ibm_context['SCORE'], country=ibm_context['COUNTRY'],
                                  category=ibm_context['CATEGORY'])
                    ibm.save()
                val_list.append(ibm_context)
                del ibm_context
            else:
                ibm_context = {}
                try:
                    ibm_db = Ibm_Hash.objects.get(hash=val)
                    ibm_context['HASH'], ibm_context['FAMILY'], ibm_context['TYPE'], ibm_context[
                        'RISK'] = ibm_db.hash, ibm_db.family, ibm_db.type, ibm_db.risk
                except Ibm_Hash.DoesNotExist:
                    ibm_context = ibmxforce(ibm_context=ibm_context, mode="single", selected_choice=val)
                    ibm = Ibm_Hash(hash=ibm_context['HASH'], family=ibm_context['FAMILY'], type=ibm_context['TYPE'],
                                   risk=ibm_context['RISK'])
                    ibm.save()
                val_list.append(ibm_context)
                del ibm_context
        for val in val_list:
            mydict.append(val)
        write_file = os.getcwd().replace("\\", '/')+'/media/ibm_reputation_results.csv'
        with open(write_file, 'w') as csvfile:
            try:
                fields = ['IPADDRESS', 'SCORE', 'COUNTRY', 'CATEGORY']
                csvwrite = csv.DictWriter(csvfile, lineterminator='\n', fieldnames=fields)
                csvwrite.writeheader()
                csvwrite.writerows(mydict)
            except:
                fields = ['HASH', 'FAMILY', 'TYPE', 'RISK']
                csvwrite = csv.DictWriter(csvfile, lineterminator='\n', fieldnames=fields)
                csvwrite.writeheader()
                csvwrite.writerows(mydict)

        context = {
            'ibm_file': '/media/ibm_reputation_results.csv'
        }
    return render(request, 'check/ibm.html', {'reputation': context})

# ===============================
#   IPVOID CHECK (check/ipvoid)
# ===============================
def ipvoid(request):
    single = request.POST.get('singledata')
    bulk = request.POST.get('bulkdata[]')
    ipv_context, context = {}, {}
    # ------------------------------
    #   SINGLE CHECK (IPADDRESS)
    # ------------------------------
    if single != None:
        val = single.strip()
        if is_valid_ip(val):
            try:
                ipv_db = Ipvoid_Ip.objects.get(ipadd=val)
                ipv_context['IPADDRESS'], ipv_context['SCORE'], ipv_context['COUNTRY'], ipv_context[
                    'CITY'] = ipv_db.ipadd, ipv_db.score, ipv_db.country, ipv_db.city
            except Ipvoid_Ip.DoesNotExist:
                ipv_context = ipvoid_data(ipv_context=ipv_context, mode="single", selected_choice=val)
                ipv = Ipvoid_Ip(ipadd=val, score=ipv_context['SCORE'], country=ipv_context['COUNTRY'],
                                city=ipv_context['CITY'])
                ipv.save()
            except:
                return render(request, 'check/Service_Unavailable.html', {'data': 'IPVoid'})
        context = {
            'ipv_data':ipv_context
        }

    # --------------------------
    #   BULK CHECK (IPADDRESS)
    # --------------------------
    elif bulk != None:
        bulk_list, ipv_data = [], {}
        for data in str(bulk).split(','):
            val = data.strip()
            if is_valid_ip(val):
                ipv_context = {}
                try:
                    ipv_db = Ipvoid_Ip.objects.get(ipadd=val)
                    ipv_context['IPADDRESS'], ipv_context['SCORE'], ipv_context['COUNTRY'], ipv_context[
                        'CITY'] = ipv_db.ipadd, ipv_db.score, ipv_db.country, ipv_db.city
                except Ipvoid_Ip.DoesNotExist:
                    ipv_context = ipvoid_data(ipv_context=ipv_context, mode="single", selected_choice=val)
                    ipv = Ipvoid_Ip(ipadd=val, score=ipv_context['SCORE'], country=ipv_context['COUNTRY'],
                                    city=ipv_context['CITY'])
                    ipv.save()
                ipv_data[val] = ipv_context
        context = {
            'ipv_bulk' :ipv_data
        }

    # -----------------------------------
    #   UPLOAD FILE TO CHECK (IPADDRESS)
    # -----------------------------------
    elif request.POST and request.FILES['myfile']:
        file_list, mydict = [], []
        file = request.FILES['myfile']
        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        uploaded_file_url = fs.url(filename)
        file_name = os.getcwd().replace("\\", '/') + uploaded_file_url
        with open(file_name, 'r', encoding='utf-8') as csvfile:
            read = csv.reader(csvfile)
            for row in read:
                if row[0] not in ['None', 'none', None, '-', '']:
                    file_list.append(row[0])
                elif row[1] not in [None, 'none', 'None', '-', '']:
                    file_list.append(row[1])
        for data in file_list:
            val = data.strip()
            if is_valid_ip(val):
                ipv_context = {}
                try:
                    ipv_db = Ipvoid_Ip.objects.get(ipadd=val)
                    ipv_context['IPADDRESS'], ipv_context['SCORE'], ipv_context['COUNTRY'], ipv_context[
                        'CITY'] = ipv_db.ipadd, ipv_db.score, ipv_db.country, ipv_db.city
                except Ipvoid_Ip.DoesNotExist:
                    ipv_context = ipvoid_data(ipv_context=ipv_context, mode="single", selected_choice=val)
                    ipv = Ipvoid_Ip(ipadd=val, score=ipv_context['SCORE'], country=ipv_context['COUNTRY'],
                                    city=ipv_context['CITY'])
                    ipv.save()
                mydict.append(ipv_context)
        write_file = os.getcwd().replace("\\", '/') + '/media/ipvoid_reputation_results.csv'
        with open(write_file, 'w') as csvfile:
            fields = ['IPADDRESS', 'SCORE', 'COUNTRY', 'CITY']
            csvwrite = csv.DictWriter(csvfile, lineterminator='\n', fieldnames=fields)
            csvwrite.writeheader()
            csvwrite.writerows(mydict)
        context = {
            'ipvoid_file': '/media/ipvoid_reputation_results.csv'
        }

    return render(request, 'check/ipvoid.html', {'reputation':context})

# ================================
#   IPLOCATION (check/iplocation)
# ================================
def iplocation(request):
    single = request.POST.get('single')
    bulk = request.POST.get('bulk')
    loc_context, context = {}, {}
    # ------------------------------
    #   SINGLE CHECK (IPADDRESS)
    # ------------------------------
    if single != None:
        val = single.strip()
        try:
            loc_db = IPLocation.objects.get(ipadd=val)
            loc_context['IPADDRESS'], loc_context['COUNTRY'], loc_context['CITY'], loc_context['REGION'], loc_context[
                'ISP'], loc_context['LATITUDE'], loc_context[
                'LONGITUDE'] = loc_db.ipadd, loc_db.country, loc_db.city, loc_db.region, loc_db.isp, loc_db.lat, loc_db.lon
        except IPLocation.DoesNotExist:
            loc_context = iploc(loc_context=loc_context, mode='single', selected_choice=val)
            ip_loc = IPLocation(ipadd=loc_context['IPADDRESS'], country=loc_context['COUNTRY'],
                                city=loc_context['CITY'], region=loc_context['REGION'], isp=loc_context['ISP'],
                                lat=loc_context['LATITUDE'], lon=loc_context['LONGITUDE'])
            ip_loc.save()
        context = {
            'ipvoid': loc_context
        }
    # -----------------------------
    #   BULK CHECK (IPADDRESS)
    # -----------------------------
    if bulk != None:
        iploc_data = {}
        for data in str(bulk).split(','):
            val = data.strip()
            if is_valid_ip(val):
                loc_context = {}
                try:
                    loc_db = IPLocation.objects.get(ipadd=val)
                    loc_context['IPADDRESS'], loc_context['COUNTRY'], loc_context['CITY'], loc_context['REGION'], \
                    loc_context[
                        'ISP'], loc_context['LATITUDE'], loc_context[
                        'LONGITUDE'] = loc_db.ipadd, loc_db.country, loc_db.city, loc_db.region, loc_db.isp, loc_db.lat, loc_db.lon
                except IPLocation.DoesNotExist:
                    loc_context = iploc(loc_context=loc_context, mode='single', selected_choice=val)
                    ip_loc = IPLocation(ipadd=loc_context['IPADDRESS'], country=loc_context['COUNTRY'],
                                        city=loc_context['CITY'], region=loc_context['REGION'], isp=loc_context['ISP'],
                                        lat=loc_context['LATITUDE'], lon=loc_context['LONGITUDE'])
                    ip_loc.save()
                iploc_data[val] = loc_context
                del loc_context
        context = {
            'ipvoid_bulk':iploc_data
        }
    return render(request, 'check/iplocation.html', {'reputation':context})


# =========================================
#   VIRUS TOTAL CHECK (check/virustotal)
# =========================================
def virustotal(request):
    single = request.POST.get('single')
    bulk = request.POST.get('bulkdata[]')
    vt_context, context = {}, {}
    # --------------------------------
    #   SINGLE CHECK (URL / HASH)
    # --------------------------------
    if single != None:
        val = single.strip()
        if is_valid_url(val):
            try:
                vt_db = Virus_Total_Url.objects.get(url=val)
                vt_context['URL'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['BLACKLIST'], vt_context['LINk'] = vt_db.url, vt_db.scan_id, vt_db.score, vt_db.blacklist, vt_db.link
            except Virus_Total_Url.DoesNotExist:
                vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                vtotal_db = Virus_Total_Url(url=vt_context['URL'], scan_id=vt_context['SCAN_ID'], score=vt_context['SCORE'], blacklist=vt_context['BLACKLIST'], link=vt_context['LINK'])
                vtotal_db.save()
        else:
            try:
                vt_db = Virus_Total_Hash.objects.get(hash=val)
                vt_context['HASH'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['MD5'], vt_context['SHA256'], vt_context['SHA1'], vt_context['LINK'], vt_context['BLACKLIST'] = vt_db.hash, vt_db.scan_id, vt_db.score, vt_db.md5, vt_db.sha256, vt_db.sha1, vt_db.link, vt_db.blacklist
            except Virus_Total_Hash.DoesNotExist:
                vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                vtotal_db = Virus_Total_Hash(hash=vt_context['HASH'], scan_id=vt_context['SCAN_ID'],score=vt_context['SCORE'], md5=vt_context['MD5'], sha256=vt_context['SHA256'], sha1=vt_context['SHA1'], blacklist=vt_context['BLACKLIST'], link=vt_context['LINK'])
                vtotal_db.save()
        context = {
            'virustotal':vt_context
        }
    # -------------------------------
    #   BULK CHECK (URL / HASH)
    # -------------------------------
    elif bulk != None:
        vt_data = {}
        for data in str(bulk).split(','):
            val = data.strip()
            vt_context = {}
            if is_valid_url(val):
                try:
                    vt_db = Virus_Total_Url.objects.get(url=val)
                    vt_context['URL'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['BLACKLIST'], vt_context[
                        'LINk'] = vt_db.url, vt_db.scan_id, vt_db.score, vt_db.blacklist, vt_db.link
                except Virus_Total_Url.DoesNotExist:
                    vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                    vtotal_db = Virus_Total_Url(url=vt_context['URL'], scan_id=vt_context['SCAN_ID'],
                                                score=vt_context['SCORE'], blacklist=vt_context['BLACKLIST'],
                                                link=vt_context['LINK'])
                    vtotal_db.save()
                vt_data[val] = vt_context
            else:
                try:
                    vt_db = Virus_Total_Hash.objects.get(hash=val)
                    vt_context['HASH'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['MD5'], vt_context[
                        'SHA256'], vt_context['SHA1'], vt_context['LINK'], vt_context[
                        'BLACKLIST'] = vt_db.hash, vt_db.scan_id, vt_db.score, vt_db.md5, vt_db.sha256, vt_db.sha1, vt_db.link, vt_db.blacklist
                except Virus_Total_Hash.DoesNotExist:
                    vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                    vtotal_db = Virus_Total_Hash(hash=vt_context['HASH'], scan_id=vt_context['SCAN_ID'],
                                                 score=vt_context['SCORE'], md5=vt_context['MD5'],
                                                 sha256=vt_context['SHA256'], sha1=vt_context['SHA1'],
                                                 blacklist=vt_context['BLACKLIST'], link=vt_context['LINK'])
                    vtotal_db.save()
                vt_data[val] = vt_context
        context = {
            'virustotal_bulk': vt_data
        }

    # --------------------------------
    #   FILES CHECK (URL / HASH)
    # --------------------------------
    elif request.POST and request.FILES['upload']:
        file_list, val_list, mydict = [], [], []
        file = request.FILES['upload']
        fs = FileSystemStorage()
        filename = fs.save(file.name, file)
        uploaded_file_url = fs.url(filename)
        file_name = os.getcwd().replace("\\", '/') + uploaded_file_url
        with open(file_name, 'r', encoding='utf-8') as csvfile:
            read = csv.reader(csvfile)
            for row in read:
                if row[0] not in ['None', 'none', None, '-', '']:
                    file_list.append(row[0])
                elif row[1] not in [None, 'none', 'None', '-', '']:
                    file_list.append(row[1])
        for data in file_list:
            val = data.strip()
            vt_context = {}
            if is_valid_url(val):
                try:
                    vt_db = Virus_Total_Url.objects.get(url=val)
                    vt_context['URL'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['BLACKLIST'], vt_context[
                        'LINk'] = vt_db.url, vt_db.scan_id, vt_db.score, vt_db.blacklist, vt_db.link
                except Virus_Total_Url.DoesNotExist:
                    vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                    vtotal_db = Virus_Total_Url(url=vt_context['URL'], scan_id=vt_context['SCAN_ID'],
                                                score=vt_context['SCORE'], blacklist=vt_context['BLACKLIST'],
                                                link=vt_context['LINK'])
                    vtotal_db.save()
                mydict.append(vt_context)
            else:
                try:
                    vt_db = Virus_Total_Hash.objects.get(hash=val)
                    vt_context['HASH'], vt_context['SCAN_ID'], vt_context['SCORE'], vt_context['MD5'], vt_context[
                        'SHA256'], vt_context['SHA1'], vt_context['LINK'], vt_context[
                        'BLACKLIST'] = vt_db.hash, vt_db.scan_id, vt_db.score, vt_db.md5, vt_db.sha256, vt_db.sha1, vt_db.link, vt_db.blacklist
                except Virus_Total_Hash.DoesNotExist:
                    vt_context = virustotal_data(vt_context=vt_context, mode='single', selected_choice=val)
                    try:
                        vtotal_db = Virus_Total_Hash(hash=vt_context['HASH'], scan_id=vt_context['SCAN_ID'],
                                                     score=vt_context['SCORE'], md5=vt_context['MD5'],
                                                     sha256=vt_context['SHA256'], sha1=vt_context['SHA1'],
                                                     blacklist=vt_context['BLACKLIST'], link=vt_context['LINK'])
                        vtotal_db.save()
                    except:
                        pass
                mydict.append(vt_context)

        write_file = os.getcwd().replace("\\", '/') + '/media/virustotal_reputation_results.csv'
        with open(write_file, 'w') as csvfile:
            try:
                fields = ['URL', 'SCAN_ID', 'SCORE', 'BLACKLIST', 'LINK']
                csvwrite = csv.DictWriter(csvfile, lineterminator='\n', fieldnames=fields)
                csvwrite.writeheader()
                csvwrite.writerows(mydict)
            except ValueError:
                fields = ['HASH', 'SCAN_ID', 'SCORE', 'MD5', 'SHA256', 'SHA1', 'BLACKLIST', 'LINK']
                csvwrite = csv.DictWriter(csvfile, lineterminator='\n', fieldnames=fields)
                csvwrite.writeheader()
                csvwrite.writerows(mydict)
        context = {
            'virustotal_file': '/media/virustotal_reputation_results.csv'
        }


    return render(request, 'check/virustotal.html', {'reputation':context})

# ====================================================
#   GENERATE REPORT (IPADDRESS / DOMAIN / URL / HASH)
# ====================================================
def report(request):
    data = request.POST.get('q')
    if data == None:
        return render(request, 'check/report.html')
    else:
        return render(request, 'check/Service_Unavailable.html', {'data':'Threat Verifica'})

# =====================================
#   IBM API KEYS TO STORE IN DATABASE
# =====================================
def ibm_api(request):
    api_key = request.POST.get('apikey')
    api_pass = request.POST.get('apipass')
    check = request.POST.get('ibm')
    send_popup = {'data':'False'}
    if check == "on":
        ibm = Ibm_API_Credits(api_key=api_key, api_password=api_pass)
        ibm.save()
        send_popup = {'data':'True'}
    return render(request, 'check/settings.html', {'alert':send_popup})

# =========================================
#   VIRUSTOTAL KEYS TO STORE IN DATABASE
# =========================================
def virustotal_api(request):
    api_key = request.POST.get('virustotal_api_key')
    check = request.POST.get('virustotal')
    send_popup = {'data':'False'}
    if check == 'on':
        vt = Virus_Total_Credits(apikey=api_key)
        vt.save()
        send_popup = {'data':'True'}
    return render(request, 'check/settings.html', {'alert':send_popup})

# =============================
#   SETTINGS TO ADD API KEYS
# =============================
def settings(request):
    return render(request, 'check/settings.html')
