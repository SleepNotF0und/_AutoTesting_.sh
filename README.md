Automation bash script which automate some security tasks from my bug bounty methology  
.  
## Key Features:- 
###  1. Run Arjun Parameter Discovery on the Target
. 
###  2. Collect Target's Archive Urls:-
......using waymore.py  
......using urlfinder  
......using gau  
(Migrate result & filter unique urls)  
.  
### 3- Run Custom Vulnerabilities Test:-  
......Error-Based SQLi  
......Time-Based SQLi  
......Secret Header Fuzzing  
......Testing HTTP-SSRF
......Sending BXSS Payloads in headers  
......Testing LFI  
......Testing Open Redirect  
.  
### 4- Js Path Crawl & Secrets  
.......Analyze Main target JS Files + Archive JS Files
.......Crawel Js files with Katana Tool
.......Run SecretFinder to discover secrets in JS Files
.......Crawel unqiue pathes using HTTP Methods [GET, POST, PUT]  
.......Hunt The DOM XSS PostMessage from the JS Files  
.  
.  
### USAGE:-  
./_AutoTesting_.sh -d https://dpduk-p-life-d2.web.app
.  
.  
### REQUIREMENTS:-  
waymore.py  
urlfinder Bash  
gau bash  
httpx bash  
SecretFinder.py  
qsreplace bash  
nuclei bash  
LFI-small.txt
HTTP-SSRF.py
Katana
Arjun
