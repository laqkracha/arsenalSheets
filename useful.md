# Useful commands

% UsefulCommands

## hostDiscover - extract IPs
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
cat <nmap-shOut> | grep report | awk '{print $NF}'
```

## hashcat - create list using rules
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
hashcat --force <passwordlist> -r <customrule> --stdout | sort -u > mut_password.list
```