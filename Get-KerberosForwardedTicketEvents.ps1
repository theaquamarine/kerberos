./TicketFlags

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

$events = Get-WinEvent -FilterXml $onlyTicketOptionEvents
$xml = $events | % {[xml]$event.ToXml()}
# $xml | ? {[int](Select-Xml -Xml $_ -Namespace @{ x = 'http://schemas.microsoft.com/win/2004/08/events/event' } -XPath '//x:Data[@Name="TicketOptions"]' | select -ExpandProperty node | select -ExpandProperty '#text') -band [TicketFlags]::Forwarded}
$filteredEvents = $xml | ? {[int]((Select-Xml -Xml $_ -Namespace @{ x = 'http://schemas.microsoft.com/win/2004/08/events/event' } -XPath '//x:Data[@Name="TicketOptions"]').node.'#text') -band [TicketFlags]::Forwarded}

# $filtered events has xml versions of all events eg
$filteredEvents.Event.EventData.Data

# events with ImpersonationLevel = Delegation / %%1840 https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
$delegationLoginEvents = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[EventData[Data[@Name='ImpersonationLevel']='%%1840']]</Select>
  </Query>
</QueryList>
"@
