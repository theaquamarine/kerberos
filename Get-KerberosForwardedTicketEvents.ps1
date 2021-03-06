./TicketFlags

# Only events with a TickeOptions field - 4768, 4769, probably others...
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

# .Event.EventData.data | ? Name -eq TicketOptions).'#text'}
# XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);  
# $nsmgr = [System.Xml.XmlNamespaceManager]::new(
# $nsmgr.AddNamespace("x", "http://schemas.microsoft.com/win/2004/08/events/event"); 
# $xml.SelectNodes('//x:Data[@Name="TicketOptions"]',$nsmgr)
