# WebPassiveInfoGather

% WebPassiveInfoGather

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

