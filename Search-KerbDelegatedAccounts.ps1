[CmdletBinding()]
Param
(
    # start the search at this DN. Default is to search all of the domain.
    [string]$DN = (Get-ADDomain).DistinguishedName
)

$SERVER_TRUST_ACCOUNT = 0x2000
$TRUSTED_FOR_DELEGATION = 0x80000
$TRUSTED_TO_AUTH_FOR_DELEGATION= 0x1000000
$PARTIAL_SECRETS_ACCOUNT = 0x4000000
$bitmask = $TRUSTED_FOR_DELEGATION -bor $TRUSTED_TO_AUTH_FOR_DELEGATION -bor $PARTIAL_SECRETS_ACCOUNT

# LDAP filter to find all accounts having some form of delegation.
# 1.2.840.113556.1.4.804 is an OR query.
$filter = @"
(&
  (servicePrincipalname=*)
  (|
    (msDS-AllowedToActOnBehalfOfOtherIdentity=*)
    (msDS-AllowedToDelegateTo=*)
    (UserAccountControl:1.2.840.113556.1.4.804:=$bitmask)
  )
  (|
    (objectcategory=computer)
    (objectcategory=person)
    (objectcategory=msDS-GroupManagedServiceAccount)
    (objectcategory=msDS-ManagedServiceAccount)
  )
)
"@ -replace "[\s\n]", ''

$propertylist = @(
    "servicePrincipalname",
    "useraccountcontrol",
    "samaccountname",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "pwdlastset"
    'LastLogonTimeStamp'
)

Function DecodeUserAccountControl ([int]$UAC) {
    <#
    .SYNOPSIS
        Convert an object's UserAccountControl value to flags
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        http://woshub.com/decoding-ad-useraccountcontrol-value/
    #>
    $UACPropertyFlags = @(
    "SCRIPT",
    "ACCOUNTDISABLE",
    "RESERVED",
    "HOMEDIR_REQUIRED",
    "LOCKOUT",
    "PASSWD_NOTREQD",
    "PASSWD_CANT_CHANGE",
    "ENCRYPTED_TEXT_PWD_ALLOWED",
    "TEMP_DUPLICATE_ACCOUNT",
    "NORMAL_ACCOUNT",
    "RESERVED",
    "INTERDOMAIN_TRUST_ACCOUNT",
    "WORKSTATION_TRUST_ACCOUNT",
    "SERVER_TRUST_ACCOUNT",
    "RESERVED",
    "RESERVED",
    "DONT_EXPIRE_PASSWORD",
    "MNS_LOGON_ACCOUNT",
    "SMARTCARD_REQUIRED",
    "TRUSTED_FOR_DELEGATION",
    "NOT_DELEGATED",
    "USE_DES_KEY_ONLY",
    "DONT_REQ_PREAUTH",
    "PASSWORD_EXPIRED",
    "TRUSTED_TO_AUTH_FOR_DELEGATION",
    "RESERVED",
    "PARTIAL_SECRETS_ACCOUNT"
    "RESERVED"
    "RESERVED"
    "RESERVED"
    "RESERVED"
    "RESERVED"
    )
    $Attributes = ""
    1..($UACPropertyFlags.Length) | Where-Object {$UAC -bAnd [math]::Pow(2,$_)} | ForEach-Object {If ($Attributes.Length -EQ 0) {$Attributes = $UACPropertyFlags[$_]} Else {$Attributes = $Attributes + " | " + $UACPropertyFlags[$_]}}
    Return $Attributes
}

<#
.Synopsis
    Search the domain for accounts with Kerberos Delegation.
.DESCRIPTION
    Kerberos Delegation is a security sensitive configuration. Especially
    full (unconstrained) delegation has significant impact: any service
    that is configured with full delegation can take any account that
    authenticates to it, and impersonate that account for any other network
    service that it likes. So, if a Domain Admin were to use that service,
    the service in turn could read the hash of KRBRTG and immediately
    effectuate a golden ticket. Etc :)

    This scripts searches AD for regular forms of delegation: full, constrained,
    and resource based. It dumps the account names with relevant information (flags)
    and adds a comment field for special cases. The output is a PSObject that
    you can use for further analysis.

    Note regarding resource based delegation: the script dumps the target
    services, not the actual service doing the delegation. I did not bother
    to parse that out.

    Main takeaway: chase all services with unconstrained delegation. If
    these are _not_ DC accounts, reconfigure them with constrained delegation,
    OR claim them als DCs from a security perspective. Meaning, that the AD
    team manages the service and the servers it runs on.

.EXAMPLE
   .\Search-KerbDelegatedAccounts.ps1 | out-gridview
.EXAMPLE
   .\Search-KerbDelegatedAccounts.ps1 -DN "ou=myOU,dc=sol,dc=local"
.NOTES
    Version:        0.1 : first version.
                    0.2 : expanded LDAP filter and comment field.
    Author:         Willem Kasdorp, Microsoft.
    Creation Date:  1/10/2016
    Last modified:  4/11/2017
#>

Get-ADObject -LDAPFilter $filter -SearchBase $DN -SearchScope Subtree -Properties $propertylist -PipelineVariable account | ForEach-Object {
    $accountDisabled = ($account.useraccountcontrol -band 2) -ne 0
    $isDC = ($account.useraccountcontrol -band $SERVER_TRUST_ACCOUNT) -ne 0
    $fullDelegation = ($account.useraccountcontrol -band $TRUSTED_FOR_DELEGATION) -ne 0
    # $constrainedDelegation = ($account.'msDS-AllowedToDelegateTo').count -gt 0
    $constrainedDelegation = ($account.useraccountcontrol -band $TRUSTED_TO_AUTH_FOR_DELEGATION) -ne 0
    $isRODC = ($account.useraccountcontrol -band $PARTIAL_SECRETS_ACCOUNT) -ne 0
    $resourceDelegation = $account.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null

    $comment = ""
    if ((-not $isDC) -and $fullDelegation) {
        $comment += "WARNING: full delegation to non-DC is not recommended!; "
    }
    if ($isRODC) {
        $comment += "WARNING: investigation needed if this is not a real RODC; "
    }
    if ($resourceDelegation) {
        # to count it using PS, we need the object type to select the correct function... broken, but there we are.
        $comment += "INFO: Account allows delegation FROM other server(s); "
    }
    if ($constrainedDelegation) {
        $comment += "INFO: constrained delegation service count: $(($account.'msDS-AllowedToDelegateTo').count); "
    }

    [PSCustomobject] @{
        samaccountname = $account.samaccountname
        objectClass = $account.objectclass
        accountDisabled = $accountDisabled
        lastLogonTimestamp = [datetime]::FromFileTime($account.LastLogonTimeStamp).ToString('s')
        pwdlastset = [datetime]::FromFileTime($account.pwdlastset).ToString('s')
        isDC = $isDC
        isRODC = $isRODC
        fullDelegation = $fullDelegation
        constrainedDelegation = $constrainedDelegation
        resourceDelegation = $resourceDelegation
        uac = ('{0:x}' -f $account.useraccountcontrol)
        flags = DecodeUserAccountControl ($account.useraccountcontrol)
        comment = $comment
        allowedToDelegateTo = $account.'msDS-AllowedToDelegateTo' -join '; '
    }
}

