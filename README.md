# Splunk_TA_nix_auditdlog
auditd.log mapping to CIM

## Background
1. There are a bunch of OOTB detections for linux endpoint that rely on Endpoint datamodel here: https://github.com/splunk/security_content/tree/develop/detections/endpoint
2. Most are based on Sysmon for linux (each detection has a dataset it was tested on in the definition https://github.com/splunk/security_content/tree/develop/detections/endpoint)
3. If we have a system with auditd and *nix TA can we leverage these OOTB detections by mapping the data from auditd.log to Endpoint datamodel?

## Example

### Linux Add User Account: https://github.com/splunk/security_content/blob/develop/detections/endpoint/linux_add_user_account.yml

1. Install auditd with policy described here: https://github.com/Neo23x0/auditd/blob/master/audit.rules
2. Instal nix TA on Splunk
3. Install linux TA on Splunk
4. Configure rlog.sh input (input from nix TA, sourcetype from linux TA):

[script://./bin/rlog.sh]
sourcetype = linux:audit
source = auditd
interval = 60
disabled = 0
index=test_auditd_nov_22


6. Now run a command "useradd test-auditd-user"

Auditd.log

type=ADD_GROUP msg=audit(1668782002.286:2759): pid=196692 uid=0 auid=1000 ses=131 subj=? msg='op=adding group acct="test-auditd-user" exe="/usr/sbin/useradd" hostname=hellosplunk-VirtualBox addr=? terminal=pts/1 res=success'
type=SYSCALL msg=audit(1668782002.286:2759): arch=c000003e syscall=44 success=yes exit=148 a0=3 a1=7fffc35833f0 a2=94 a3=0 items=0 ppid=194645 pid=196692 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=131 comm="useradd" exe="/usr/sbin/useradd" subj=? key=(null)
type=PROCTITLE msg=audit(1668782002.286:2759): proctitle=7573657261646400746573742D6175646974642D75736572
type=UNKNOWN[1420] msg=audit(1668782002.286:2759): subj_apparmor=unconfined
type=ADD_USER msg=audit(1668782002.294:2760): pid=196692 uid=0 auid=1000 ses=131 subj=? msg='op=adding user id=1004 exe="/usr/sbin/useradd" hostname=hellosplunk-VirtualBox addr=? terminal=pts/1 res=success'
type=SYSCALL msg=audit(1668782002.294:2760): arch=c000003e syscall=44 success=yes exit=132 a0=3 a1=7fffc3583210 a2=84 a3=0 items=0 ppid=194645 pid=196692 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=131 comm="useradd" exe="/usr/sbin/useradd" subj=? key=(null)
type=PROCTITLE msg=audit(1668782002.294:2760): proctitle=7573657261646400746573742D6175646974642D75736572


ausearch/Splunk


type=SYSCALL msg=audit(11/18/2022 14:33:22.294:2760) : arch=x86_64 syscall=sendto success=yes exit=132 a0=0x3 a1=0x7fffc3583210 a2=0x84 a3=0x0 items=0 ppid=194645 pid=196692 auid=hello-splunk uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=131 comm=useradd exe=/usr/sbin/useradd subj=? key=(null) 
type=PROCTITLE msg=audit(11/18/2022 14:33:22.294:2760) : proctitle=useradd test-auditd-user 
type=ADD_USER msg=audit(11/18/2022 14:33:22.294:2760) : pid=196692 uid=root auid=hello-splunk ses=131 subj=? msg='op=adding user id=test-auditd-user exe=/usr/sbin/useradd hostname=hellosplunk-VirtualBox addr=? terminal=pts/1 res=success' 

type=SYSCALL msg=audit(11/18/2022 14:33:22.286:2759) : arch=x86_64 syscall=sendto success=yes exit=148 a0=0x3 a1=0x7fffc35833f0 a2=0x94 a3=0x0 items=0 ppid=194645 pid=196692 auid=hello-splunk uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=131 comm=useradd exe=/usr/sbin/useradd subj=? key=(null) 
type=PROCTITLE msg=audit(11/18/2022 14:33:22.286:2759) : proctitle=useradd test-auditd-user 
type=ADD_GROUP msg=audit(11/18/2022 14:33:22.286:2759) : pid=196692 uid=root auid=hello-splunk ses=131 subj=? msg='op=adding group acct=test-auditd-user exe=/usr/sbin/useradd hostname=hellosplunk-VirtualBox addr=? terminal=pts/1 res=success' 


Sysmon for linux/Splunk

Nov 18 14:33:22 hellosplunk-VirtualBox sysmon: <Event><System><Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="2022-11-18T14:33:22.281954000Z"/><EventRecordID>421210</EventRecordID><Correlation/><Execution ProcessID="21004" ThreadID="21004"/><Channel>Linux-Sysmon/Operational</Channel><Computer>hellosplunk-VirtualBox</Computer><Security UserId="0"/></System><EventData><Data Name="RuleName">-</Data><Data Name="UtcTime">2022-11-13 19:44:06.867</Data><Data Name="ProcessGuid">{8ef76b8e-4906-6371-35c5-783f95550000}</Data><Data Name="ProcessId">196692</Data><Data Name="Image">/usr/sbin/useradd</Data><Data Name="FileVersion">-</Data><Data Name="Description">-</Data><Data Name="Product">-</Data><Data Name="Company">-</Data><Data Name="OriginalFileName">-</Data><Data Name="CommandLine">useradd test-auditd-user</Data><Data Name="CurrentDirectory">/var/tmp</Data><Data Name="User">root</Data><Data Name="LogonGuid">{8ef76b8e-0000-0000-0000-000001000000}</Data><Data Name="LogonId">0</Data><Data Name="TerminalSessionId">131</Data><Data Name="IntegrityLevel">no level</Data><Data Name="Hashes">-</Data><Data Name="ParentProcessGuid">{8ef76b8e-3dbe-6371-d586-209f9c550000}</Data><Data Name="ParentProcessId">194645</Data><Data Name="ParentImage">/usr/bin/bash</Data><Data Name="ParentCommandLine">-bash</Data><Data Name="ParentUser">root</Data></EventData></Event>


7. The linux TA says do enriched logs instead of RAW, lets see if there is any difference - doesbnt seem to be much different

type=SYSCALL msg=audit(11/21/2022 10:29:54.556:3009) : arch=x86_64 syscall=sendto success=yes exit=132 a0=0x3 a1=0x7ffcda14f9a0 a2=0x84 a3=0x0 items=0 ppid=209047 pid=209213 auid=hello-splunk uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=144 comm=useradd exe=/usr/sbin/useradd subj=? key=(null) 
type=PROCTITLE msg=audit(11/21/2022 10:29:54.556:3009) : proctitle=useradd test-enrich-log 
type=ADD_USER msg=audit(11/21/2022 10:29:54.556:3009) : pid=209213 uid=root auid=hello-splunk ses=144 subj=? msg='op=adding user id=unknown(1007) exe=/usr/sbin/useradd hostname=hellosplunk-VirtualBox addr=? terminal=pts/1 res=success' 

type=SYSCALL msg=audit(11/21/2022 10:29:54.544:3008) : arch=x86_64 syscall=sendto success=yes exit=148 a0=0x3 a1=0x7ffcda14fb80 a2=0x94 a3=0x0 items=0 ppid=209047 pid=209213 auid=hello-splunk uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=144 comm=useradd exe=/usr/sbin/useradd subj=? key=(null) 
type=PROCTITLE msg=audit(11/21/2022 10:29:54.544:3008) : proctitle=useradd test-enrich-log 
type=ADD_GROUP msg=audit(11/21/2022 10:29:54.544:3008) : pid=209213 uid=root auid=hello-splunk ses=144 subj=? msg='op=adding group acct=test-enrich-log exe=/usr/sbin/useradd hostname=hellosplunk-VirtualBox addr=? terminal=pts/1 res=success' 


8. TA-auditd-linux does field extractions better with props. But it does not map to Endpoint datamodel (instead goes to auditd data model). 
9. TA linux does mapping to datamodels but is not complete
10. For Endpoint.Processes datamodel need tags {process, report}. Use extractions from auditd TA and datamodel mapping example from TA linux

