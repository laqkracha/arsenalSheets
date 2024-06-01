# Fuzzing

% Fuzzing

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
gobuster vhost -u http://runner.htb -w wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
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
