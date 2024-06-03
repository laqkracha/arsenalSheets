# CPTS 

% CPTS

## Banner Grabbing - nc
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -nv <ip> <port>
```

## Banner Grabbing - tcpdump
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo tcpdump -i <interface> port <port> -w <out.pcap>
```

## nmap - scripts category 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> --script <category>
```

##  nmap - optimized RTT
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

##  nmap - optimized retries
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> --max-retries <retries>
```

##  nmap - optimized rate (bandwith) - packets simultaneously
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> --min-rate <packets>
```

##  nmap - optimized timing
#plateform/linux #target/remote #port/ #protocol/http #cat/ATTACK/
```
sudo nmap <target> -T<0-5>
```

##  nmap - Firewall & IDS/IPS Evation - look packets flags on response
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <ip> -p <ports> -sA -Pn -n --disable-arp-ping --packet-trace
```

##  nmap - decoys to vary IP's on IP header
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> -p <ports> -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

## nmap - w/ different source IP 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> -n -Pn -p <ports> -O -S <sourceIP> -e tun0
```

##  nmap - DNS proxying - SYN-Scan of a Filtered Port
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> -p <ports> -sS -Pn -n --disable-arp-ping --packet-trace
```

##  nmap - DNS proxying - SYN-Scan From DNS Port
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> -p<ports> -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
```

##  footprinting - domain information - crt.sh unique subdomains
#plateform/linux #target/remote #port/ #protocol/http #cat/ATTACK/
```
curl -s https://crt.sh/\?q\=<targetDomain>\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

##  footprinting - domain information - company hosted servers
#plateform/linux #target/remote #port/ #protocol/http #cat/ATTACK/
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep <targetDomain> | cut -d" " -f1,4;done
```

##  footprinting - domain information - shodan 1
#plateform/linux #target/remote #port/ #protocol/http #cat/ATTACK/
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep <targetDomain> | cut -d" " -f4 >> ip-addresses.txt;done
```

##  footprinting - domain information - shodan 2
#plateform/linux #target/remote #port/ #protocol/http #cat/ATTACK/
```
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

##  footprinting - domain information - DNS records
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dig any <targetDomain>
```

##  footprinting - cloud resources - company hosted servers
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep <targetDomain> | cut -d" " -f1,4;done
```

##  footprinting - cloud resources - domain.glass
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
chromium https://domain.glass
```

##  footprinting - FTP - anonymous login
#plateform/linux #target/remote #port/21 #protocol/ftp #cat/ATTACK/
```
ftp <ip>
```

##  footprinting - nmap search scripts
#plateform/linux #target/remote #port/ #protocol/ftp #cat/ATTACK/
```
find / -type f -name <protocol>* 2>/dev/null | grep scripts/usr/share/nmap/scripts/ftp-syst.nse
```

##  footprinting - all FTP scripts
#plateform/linux #target/remote #port/21 #protocol/ftp #cat/ATTACK/
```
sudo nmap <target> -sV -p21 --scipt ftp-*
```

##  footprinting - default script scan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <target> -sV -p<ports> -sC
```

##  footprinting - FTP with OpenSSL
#plateform/linux #target/remote #port/21 #protocol/ftp #cat/ATTACK/
```
openssl s_client -connect <target>:21 -starttls ftp
```

##  footprinting - SMB - nmap
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
sudo nmap <target> -sV -sC -p139,445
```

##  footprinting - SMB - rpcclient
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
rpcclient -U "" <target>
```

##  footprinting - SMB - brute forcing user id's
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
for i in $(seq 500 1100);do rpcclient -N -U "" <target> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

##  footprinting - SMB - Impacket Samrdump.py
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
samrdump.py <target>
```

##  footprinting - SMB - smbmap
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
smbmap -H <target>
```

##  footprinting - SMB - nxc
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
nxc smb <target> --shares -u '' -p ''
```

##  footprinting - SMB - Enum4linux-ng
#plateform/linux #target/remote #port/139,443 #protocol/smb #cat/ATTACK/
```
enum4linux <target> -AENUM4LINUX - next generation
```

##  footprinting - NFS - nmap
#plateform/linux #target/remote #port/111,2049 #protocol/nfs #cat/ATTACK/
```
sudo nmap <target> -p111,2049 -sV -sC
```

##  footprinting - NFS - nmap scripts
#plateform/linux #target/remote #port/111,2049 #protocol/nfs #cat/ATTACK/
```
sudo nmap --script nfs* <target> -sV -p111,2049
```

##  footprinting - NFS - available shares
#plateform/linux #target/remote #port/111,2049 #protocol/nfs #cat/ATTACK/
```
showmount -e <target>
```

##  footprinting - NFS - mount share
#plateform/linux #target/remote #port/111,2049 #protocol/nfs #cat/ATTACK/
```
mkdir target-NFS; sudo mount -t nfs <target>:/ ./target-NFS/ -o nolock
```

##  footprinting - NFS - umount share
#plateform/linux #target/remote #port/111,2049 #protocol/nfs #cat/ATTACK/
```
sudo umount ./target-NFS
```


##  footprinting - DNS - NameServer query
#plateform/linux #target/remote #port/53 #protocol/dns #cat/ATTACK/
```
dig ns <targetDomain> @<DNSserverToQuery>
```

##  footprinting - DNS - version query
#plateform/linux #target/remote #port/53 #protocol/dns #cat/ATTACK/
```
dig CH TXT version.bind <targetIP>
```

##  footprinting - DNS - any query
#plateform/linux #target/remote #port/53 #protocol/dns #cat/ATTACK/
```
dig any <targetDomain> @<DNSserverToQuery>
```

##  footprinting - DNS - zone transfer & zone transfer internal (just modify the target)
#plateform/linux #target/remote #port/53 #protocol/dns #cat/ATTACK/
```
dig axfr <targetDomain> @<DNSserverToQuery>
```

##  footprinting - DNS - subdomain brute forcing
#plateform/linux #target/remote #port/53 #protocol/dns #cat/ATTACK/
```
for sub in $(cat <subdomainsList>);do dig $sub.<targetDomain> @<DNSserverToQuery> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

##  footprinting - DNS - dnsenum subdomain brute forcing
#plateform/linux #target/remote #port/53 #protocol/dns #cat/ATTACK/
```
dnsenum --dnsserver <DNSserverToQuery> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt <targetDomain>
```

##  footprinting - SMTP - nmap
#plateform/linux #target/remote #port/25,587 #protocol/smtp #cat/ATTACK/
```
sudo nmap <target> -sC -sV -p25
```

##  footprinting - SMTP - nmap openrelay
#plateform/linux #target/remote #port/25,587 #protocol/smtp #cat/ATTACK/
```
sudo nmap <target> -p25 --script smtp-open-relay -v
```

##  footprinting -  IMAP/POP3 - nmap
#plateform/linux #target/remote #port/110,143,993,995 #protocol/imappop3 #cat/ATTACK/
```
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
```

##  footprinting -  IMAP/POP3 - curl
#plateform/linux #target/remote #port/110,143,993,995 #protocol/imappop3 #cat/ATTACK/
```
curl -k 'imaps://<targetIP>' --user <user>:<password>
```

##  footprinting -  IMAP/POP3 - openssl/tls interaction pop3s
#plateform/linux #target/remote #port/110,143,993,995 #protocol/pop3s #cat/ATTACK/
```
openssl s_client -connect <targetIP>:pop3s
```

##  footprinting -  IMAP/POP3 - openssl/tls interaction imap
#plateform/linux #target/remote #port/110,143,993,995 #protocol/imap #cat/ATTACK/
```
openssl s_client -connect <target>:imaps
```

##  footprinting -  SNMP - snmpwalk
#plateform/linux #target/remote #port/udp161 #protocol/snmp #cat/ATTACK/
```
snmpwalk -v2c -c public <target>
```

##  footprinting - SNMP - OneSixtyOne 
#plateform/linux #target/remote #port/udp161 #protocol/snmp #cat/ATTACK/
```
onesixtyone -c <pathSecListsSNMP.txt> <target>
```

##  footprinting - MySQL - nmap scripts
#plateform/linux #target/remote #port/3306 #protocol/mysql #cat/ATTACK/
```
sudo nmap <target> -sV -sC -p3306 --script mysql*

```

##  footprinting - MySQL - login test
#plateform/linux #target/remote #port/3306 #protocol/mysql #cat/ATTACK/
```
mysql -u root -h <target>
```

##  footprinting - MySQL - login test using password
#plateform/linux #target/remote #port/3306 #protocol/mysql #cat/ATTACK/
```
mysql -u <user> -p<password> -h <target>
```

##  footprinting - MSSQL - nmap scripts
#plateform/linux #target/remote #port/1433 #protocol/mssql #cat/ATTACK/
```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <target>
```

##  footprinting - MSSQL - msfconsole mssql ping
#plateform/linux #target/remote #port/1433 #protocol/mssql #cat/ATTACK/
```
echo -e "use auxiliary/scanner/mssql/mssql_ping\nset RHOST <target>\nrun" | msfconsole -q
```

##  footprinting - MSSQL - mssqlclient connection
#plateform/linux #target/remote #port/1433 #protocol/mssql #cat/ATTACK/
```
mssqlclient.py <user>@<target> -windows-auth
```

##  footprinting - MSSQL - nxc
#plateform/linux #target/remote #port/1433 #protocol/mssql #cat/ATTACK/
```
nxc mssql <target> -u <user> -p <password>
```

##  footprinting - Oracle TNS - odat
#plateform/linux #target/remote #port/1521 #protocol/tns #cat/ATTACK/
```
odat.py all -s <target>
```

##  footprinting - Oracle TNS - login
#plateform/linux #target/remote #port/1521 #protocol/tns #cat/ATTACK/
```
sqlplus <user>/<password>@<target>/XESQL*
```

##  footprinting - Oracle TNS - test upload file
#plateform/linux #target/remote #port/1521 #protocol/tns #cat/ATTACK/
```
echo "test file" > testing.txt; ./odat.py utlfile -s <target> -d XE -U <user> -P <password> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

##  footprinting - IPMI - dump hashes
#plateform/linux #target/remote #port/udp-623 #protocol/ipmi #cat/ATTACK/
```
echo -e "use auxiliary/scanner/ipmi/ipmi_dumphashes\nset RHOST <target>\nrun" | msfconsole -q
```

##  footprinting - SSH - sshaudit
#plateform/linux #target/remote #port22 #protocol/ssh #cat/ATTACK/
```
./ssh-audit.py <target>
```

##  footprinting - SSH - test auth methods
#plateform/linux #target/remote #port/22 #protocol/ssh #cat/ATTACK/
```
ssh -v <user>@<target>
```

##  footprinting - SSH - test auth methods
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ssh -v <user>@<target> -o PreferredAuthentications=password
```

##  footprinting - Rsync - nmap
#plateform/linux #target/remote #port/873 #protocol/rsync #cat/ATTACK/
```
sudo nmap -sV -p 873 <target>
```

##  footprinting - Rsync - probing for accesible shares 
#plateform/linux #target/remote #port/873 #protocol/rsync #cat/ATTACK/
```
nc -nv <target> 873
```

##  footprinting - Rsync - enumerating open share
#plateform/linux #target/remote #port/873 #protocol/rsync #cat/ATTACK/
```
rsync -av --list-only rsync://<target>/<share>
```

##  footprinting - Rservices - nmap
#plateform/linux #target/remote #port/512,513,514 #protocol/r-services #cat/ATTACK/
```
sudo nmap -sV -p 512,513,514 <target>
```

##  footprinting - Rservices - login
#plateform/linux #target/remote #port/512,513,514 #protocol/r-services #cat/ATTACK/
```
rlogin <target> -l <user>
```

##  footprinting - WinRM - nmap
#plateform/linux #target/remote #port/5985,5986 #protocol/winrm #cat/ATTACK/
```
nmap -sV -sC <target> -p5985,5986 --disable-arp-ping -n
```

##  footprinting - WinRM - evil-winrm
#plateform/linux #target/remote #port/5985,5986 #protocol/winrm #cat/ATTACK/
```
evil-winrm -i <target> -u <user> -p <password>
```

##  footprinting - WinRM - ncx
#plateform/linux #target/remote #port/5985,5986 #protocol/winrm #cat/ATTACK/
```
nxc winrm <target> -u <user> -p <password>
```

##  footprinting - WinRM - wmiexec
#plateform/linux #target/remote #port/135 #protocol/wmi #cat/ATTACK/
```
/usr/share/doc/python3-impacket/examples/wmiexec.py <user>:"<password>"@<target>
```

##  footprinting - RDP - nmap scripts
#plateform/linux #target/remote #port/3389 #protocol/rdp #cat/ATTACK/
```
nmap -sV -sC <target> -p3389 --script rdp*
```

##  footprinting - RDP - nmap packet trace
#plateform/linux #target/remote #port/3389 #protocol/rdp #cat/ATTACK/
```
nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
```

##  footprinting - RDP - rdpseccheck
#plateform/linux #target/remote #port/3389 #protocol/rdp #cat/ATTACK/
```
rdp-sec-check.pl <target>
```

##  footprinting - RDP - rdp connection
#plateform/linux #target/remote #port/3389 #protocol/rdp #cat/ATTACK/
```
xfreerdp /u:<user> /p:"<password>" /v:<target>
```