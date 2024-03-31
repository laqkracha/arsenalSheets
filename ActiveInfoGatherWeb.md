# WebActiveInfoGather

% WebPassiveInfoGather

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

## active web - vhost discovery with ffuf
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wordlist> -u http://<targetIP/Domain> -H "HOST: FUZZ.<targetDomain>"
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