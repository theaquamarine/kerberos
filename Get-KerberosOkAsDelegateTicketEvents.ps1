# Find events where the ticketoptions included "OkAsDelegate", meaning the service has TrustedForDelegation
. ./Get-KerberosTicketEvents.ps1
Get-KerberosTicketOptionEvents OkAsDelegate
