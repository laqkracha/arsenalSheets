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
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ -recursion -recursion-depth <depth>
```

## fuzzing - recursive with extension
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```
ffuf -w <wlist>:FUZZ -u <targetURL>/FUZZ -recursion -recursion-depth <depth> -e .<ext> -v
```

## fuzzing - 
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```

```

## fuzzing - 
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```

```

## fuzzing - 
#plateform/linux #target/remote #port/80 #protocol/http #cat/ATTACK/
```

```