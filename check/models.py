from django.db import models

# Create your models here.

# -----------------------
#   IPADDRESS TABLES
# -----------------------
class Ibm_Ip(models.Model):
    ipadd = models.CharField(max_length=100, primary_key=True)
    score = models.FloatField(max_length=10)
    country = models.CharField(max_length=50)
    category = models.CharField(max_length=200)

class Ipvoid_Ip(models.Model):
    ipadd = models.CharField(max_length=100, primary_key=True)
    score = models.CharField(max_length=10)
    country = models.CharField(max_length=50)
    city = models.CharField(max_length=50)

class IPLocation(models.Model):
    ipadd = models.CharField(max_length=100, primary_key=True)
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    region = models.CharField(max_length=100)
    isp = models.CharField(max_length=200)
    lat = models.CharField(max_length=50)
    lon = models.CharField(max_length=50)

# -------------------
#   DOMAIN TABLES
# -------------------
class Ibm_domain(models.Model):
    domain = models.CharField(max_length=100, primary_key=True)
    score = models.CharField(max_length=10)
    country = models.CharField(max_length=50)
    category = models.CharField(max_length=50)

# ------------------
#   URL TABLES
# ------------------
class Ibm_Url(models.Model):
    url = models.CharField(max_length=500, primary_key=True)
    score = models.CharField(max_length=10)
    country = models.CharField(max_length=50)
    category = models.CharField(max_length=50)

class Virus_Total_Url(models.Model):
    url = models.CharField(max_length=200, primary_key=True)
    scan_id = models.CharField(max_length=200)
    score = models.CharField(max_length=10)
    link = models.CharField(max_length=500)
    blacklist = models.CharField(max_length=1000)


# --------------------
#   HASH TABLES
# --------------------
class Ibm_Hash(models.Model):
    hash = models.CharField(max_length=500, primary_key=True)
    family = models.CharField(max_length=100)
    type = models.CharField(max_length=100)
    risk = models.CharField(max_length=10)

class Virus_Total_Hash(models.Model):
    hash = models.CharField(max_length=500, primary_key=True)
    scan_id = models.CharField(max_length=500)
    score = models.CharField(max_length=50, default='0')
    md5 = models.CharField(max_length=200)
    sha256 = models.CharField(max_length=200)
    sha1 = models.CharField(max_length=150)
    link = models.CharField(max_length=1000)
    blacklist = models.CharField(max_length=5000)


# -------------------------------
#   FILE SCANS USING VIRUSTOTAL
# -------------------------------
class Virus_Total_Scan(models.Model):
    file = models.CharField(max_length=200, primary_key=True)
    scan_id = models.CharField(max_length=200)
    score = models.CharField(max_length=100)
    md5 = models.CharField(max_length=200)
    sha256 = models.CharField(max_length=200)
    shal = models.CharField(max_length=200)
    blacklist = models.CharField(max_length=5000)
    link = models.CharField(max_length=1000)

# ------------------------
#   IBM X FORCE API KEYS
# ------------------------
class Ibm_API_Credits(models.Model):
    api_key = models.CharField(max_length=200)
    api_password = models.CharField(max_length=200)

# -------------------------
#   VIRUS TOTAL API KEYS
# -------------------------
class Virus_Total_Credits(models.Model):
    apikey = models.CharField(max_length=200)