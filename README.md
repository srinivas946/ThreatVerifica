# ThreatVerifica
Threat Verifica is a tool to notify the Malicious Rating of IPAddress, Domain, Url and Hash from the top most Threat Intelligence website using API's <br/>

### Requirements <br/>
At first you have to install some packages before using the tool<br/>
1. requests<br/>
2. beautifulsoup4<br/>
3. django<br/>

### Services Provide <br/>
- Single IPAddress / Domain / Url / Hash Check
- Bulk IPAddress / Domain / Url / Hash Checks
- Upload csv file to check IPAddress / Domain / Url / Hash Check and download the file with results
- Generate Report for provided IPAddress / Domain / Url / Hash

### How to use <br/>
**Add API Keys**<br/>
- Go to settings and get API Keys from the Threat Intelligence websites and store the API keys to your database<br/>
- Public API's have the limitations based on their bussiness trade<br/>

**Quick Check**<br/>
- You will get complete information about an IPAddress, Domain, Url, Hash in one shot<br/>
- Go to Home page, paste the data and select the checkboxes to get information from the particular source and start search<br/>

**Individual Check**<br/>
- How to get Information of a data from the particular websites?, you have that option too<br/>
- Select the website sections and perform the operations such as Single Check, Bulk Check and Check through Uploading the file<br/>
- You can also generate reports using this tool. Go to Reports Section, enter the data you will get complete information in the form of report<br/>
