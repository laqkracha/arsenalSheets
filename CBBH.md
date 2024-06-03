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
ffuf -u <targetURL>/FUZZ -w <wlist>
```

## fuzzing - pages - extension
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/<page>FUZZ
```

## fuzzing - page - page
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ.<ext>
```

## fuzzing - recursive
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ -recursion -recursion-depth <depth> -v
```

## fuzzing - recursive with extension
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ -recursion -recursion-depth <depth> -e .<ext> -v
```

## dns record to /etc/hosts
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
sudo sh -c 'echo "<IP>  <sub.domain.xxx>" >> /etc/hosts'
```

## fuzzing - subdomains
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u https://FUZZ.<targetDomain>/
```

## fuzzing - vHosts ffuf
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL> -H 'Host: FUZZ.<targetDomain>'
```

## fuzzing - vHosts gobuster
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
gobuster vhost -u <targetURL> -w <wlist> --append-domain
```

## fuzzing - GET request fuzzing (then filter by size)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u '<target>/<file>?FUZZ=key'
```

## fuzzing - POST request fuzzing (then filter by size)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <target> -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded'
```

## fuzzing - get numbers 1-1000
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

## fuzzing - value fuzzing (then filter by size)
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <target> -X POST -d '<param>=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
```