Automation bash script which automate some security tasks from my bug bounty methology  
.  
# Key Features:-  
## 1. Collect Target's Archive Urls:-
### ......using waymore.py  
### ......using urlfinder  
### ......using gau  
### (Migrate result & filter unique urls)  
.  
## 2- Run Custom Vulnerabilities Test:-  
### ......Error-Based SQLi  
### ......Time-Based SQLi  
### ......Secret Header Fuzzing  
### ......Sending BXSS Payloads in headers  
### ......Testing LFI  
### ......Testing Open Redirect  
.  
## 3- Js Path Crawl & Secrets  
### .......Analyze Main target JS Files + Archive JS Files  
### .......Crawel unqiue pathes using HTTP Methods [GET, POST, PUT]  
### .......Run SecretFinder to discover secrets in JS Files  
### .......Hunt The DOM XSS PostMessage from the JS Files  
.  
.  
.  
.
## USAGE:-  
### ./_AutoTesting_.sh -d https://dpduk-p-life-d2.web.app
.  
.  
## REQUIREMENTS:-  
waymore.py
urlfinder Bash
gau bash
httpx bash
SecretFinder.py

