. .\TicketFlags.ps1

function ReturnSessionTickets {
    <#
    .SYNOPSIS
        Get a session's Kerberos tickets, like klist ticket
    .DESCRIPTION
        Based on https://gallery.technet.microsoft.com/List-All-Cached-Kerberos-5ba41829
    #>
    param ($SessionID = $null)
    $OS = Get-CimInstance win32_operatingsystem
    if ($SessionID -eq $null) {
        $TicketsArray = klist.exe tickets
    } else {
        $TicketsArray = klist.exe tickets -li $sessionID
    }

    $Counter = 0
    foreach ($line in $TicketsArray) {
        if ($line -match "^#\d") {
            $Number = $Line.Split('>')[0] -replace '#'
            $Line1 = $Line.Split('>')[1]
            $Client = $Line1 ;	$Client = $Client.Replace('Client:', '') ; $Client = $Client.Substring(2)
            $Server = $TicketsArray[$Counter + 1]; $Server = $Server.Replace('Server:', '') ; $Server = $Server.substring(2)
            $KerbTicketEType = $TicketsArray[$Counter + 2]; $KerbTicketEType = $KerbTicketEType.Replace('KerbTicket Encryption Type:', ''); $KerbTicketEType = $KerbTicketEType.substring(2)
            $TickFlags = $TicketsArray[$Counter + 3]; $TickFlags = $TickFlags.Replace('Ticket Flags', ''); $TickFlags = $TickFlags.substring(2)
            $Flags = [TicketFlags][int]($TickFlags -split ' ')[0]
            $StartTime = $TicketsArray[$Counter + 4]; $StartTime = $StartTime.Replace('Start Time:', ''); $StartTime = $StartTime.substring(2).replace(' (local)','')
            $EndTime = $TicketsArray[$Counter + 5]; $EndTime = $EndTime.Replace('End Time:', ''); $EndTime = $EndTime.substring(4).replace(' (local)','')
            $RenewTime = $TicketsArray[$Counter + 6]; $RenewTime = $RenewTime.Replace('Renew Time:', ''); $RenewTime = $RenewTime.substring(2).replace(' (local)','')
            $SessionKey = $TicketsArray[$Counter + 7]; $SessionKey = $SessionKey.Replace('Session Key Type:', ''); $SessionKey = $SessionKey.substring(2)

            if ([int]$OS.BuildNumber -ge 9200) {
                $CacheFlags = $TicketsArray[$Counter + 8]; $CacheFlags = $CacheFlags.Replace('Cache Flags:', ''); $CacheFlags = $CacheFlags.substring(2)
                $KDCCalled = $TicketsArray[$Counter + 9]; $KDCCalled = $KDCCalled.Replace('Kdc Called:', ''); $KDCCalled = $KDCCalled.substring(2)
            }

            [PSCustomObject]@{
                Number = $Number
                Client = $Client
                Server = $Server
                'KerbTicket Encryption Type' = $KerbTicketEType
                'Ticket Flags' = $TickFlags
                Flags = '0x' + "{0:x}" -f $Flags
                FlagAttributes = $Flags
                'Start Time' = [datetime]::ParseExact($StartTime,'M/d/yyyy H:m:s',$null)
                'End Time' = [datetime]::ParseExact($EndTime,'M/d/yyyy H:m:s',$null)
                'Renew Time' = [datetime]::ParseExact($RenewTime,'M/d/yyyy H:m:s',$null)
                'Session Key Type' = $SessionKey
                'Cache Flags' = $CacheFlags
                'KDCCalled' = $KDCCalled

                Forwardable = $Flags.HasFlag([TicketFlags]::Forwardable)
                Renewable = $Flags.HasFlag([TicketFlags]::Renewable)
                PreAuthentcated = $Flags.HasFlag([TicketFlags]::PreAuthenticated)
                Canonicalize = $Flags.HasFlag([TicketFlags]::Canonicalize)
                OkAsDelegate = $Flags.HasFlag([TicketFlags]::OkAsDelegate)

            }
        }
        $Counter++

    }
}

# ReturnSessionTickets
# ReturnSessionTickets | ? OkAsDelegate | ? Server -NotMatch 'INDCSS' | Select -Expand Serve | % {$_.Server + ' ; ' + $_.FlagAttributes}
