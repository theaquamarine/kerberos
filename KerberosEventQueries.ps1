# Only events with a TicketOptions field - Audit Kerberos Authenticaiton Service & Audit Kerberos Service Ticket Operations on KDC
# https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-authentication-service
# https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-kerberos-service-ticket-operations
$onlyTicketOptionEvents = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[EventData[Data[@Name='TicketOptions']]]</Select>
  </Query>
</QueryList>
"@

# events with ImpersonationLevel = Delegation / %%1840 https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
$delegationLoginEvents = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[EventData[Data[@Name='ImpersonationLevel']='%%1840']]</Select>
  </Query>
</QueryList>
"@

# https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging
$kerberosEvents = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Security-Kerberos']]]</Select>
  </Query>
</QueryList>
"@
$KDC_ERR_S_BADOPTION = 0xD #13
$kerberosBadOptionEvents = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Security-Kerberos']] and EventData[Data[@Name='ErrorCode']='0x{0:x}']]</Select>
  </Query>
</QueryList>
"@ -f $KDC_ERR_S_BADOPTION
