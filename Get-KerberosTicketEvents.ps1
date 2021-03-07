<#
.SYNOPSIS
    Get Kerberos ticket events where the tickets have $TicketFlags set
.EXAMPLE
    PS C:\> Get-KerberosTicketOptionEvents Forwarded
    Get all events with forwarded Kerberos tickets
.OUTPUTS
    EventLogRecord[]
#>
. ./TicketFlags.ps1
. ./KerberosEventQueries.ps1

function Get-KerberosTicketOptionEvents { 
    [CmdletBinding()]
    [OutputType([System.Diagnostics.Eventing.Reader.EventLogRecord[]])]
    param (
        # The ticket flags to require
        [TicketFlags[]]$TicketFlags
    )
    
    begin {
       $events = Get-WinEvent -FilterXml $onlyTicketOptionEvents
    }
    
    process {
        if ($TicketFlags) {
            $flags = [TicketFlags]($TicketFlags -join ',')
            $events | Where-Object {
                [int]((Select-Xml -Xml ([xml]$_.ToXml()) -Namespace @{ x = 'http://schemas.microsoft.com/win/2004/08/events/event' } -XPath '//x:Data[@Name="TicketOptions"]').node.'#text') -band $flags
            }
        } else {
            $events
        }
    }
}
