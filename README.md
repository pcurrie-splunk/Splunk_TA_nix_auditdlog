# Splunk_TA_nix_auditdlog
auditd.log mapping to CIM

## Background
1. There are a bunch of OOTB detections for linux endpoint that rely on Endpoint datamodel here: https://github.com/splunk/security_content/tree/develop/detections/endpoint
2. Most are based on Sysmon for linux (each detection has a dataset it was tested on in the definition https://github.com/splunk/security_content/tree/develop/detections/endpoint)
3. If we have a system with auditd and *nix TA can we leverage these OOTB detections by mapping the data from auditd.log to Endpoint datamodel?

## Example

### Linux Add User Account: https://github.com/splunk/security_content/blob/develop/detections/endpoint/linux_add_user_account.yml

