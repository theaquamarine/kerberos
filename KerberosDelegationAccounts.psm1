# Based on Willem Kasdorp's Search-KerbDelegatedAccounts.ps1
. .\UserAccountControl.ps1

$delegationbitmask = [UserAccountControl]::TRUSTED_FOR_DELEGATION -bor
    [UserAccountControl]::TRUSTED_TO_AUTH_FOR_DELEGATION -bor
    [UserAccountControl]::PARTIAL_SECRETS_ACCOUNT

# TRUSTED_FOR_DELEGATION = Unconstrained Delegation
# TRUSTED_TO_AUTH_FOR_DELEGATION = Constrained Delegation/RBCD
# PARTIAL_SECRETS_ACCOUNT = RODC

$propertylist = @(
    "servicePrincipalname",
    "useraccountcontrol",
    "samaccountname",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "pwdlastset"
    'LastLogonTimeStamp'
)

function Get-KerberosConstrainedDelegationAccounts {
    [CmdletBinding()]
    Param (
        # start the search at this DN. Default is to search all of the domain.
        [string]$DN = (Get-ADDomain).DistinguishedName
    )
    $bitmask = [UserAccountControl]::TRUSTED_TO_AUTH_FOR_DELEGATION
    $filter = "(userAccountControl:1.2.840.113556.1.4.803:=$bitmask)"
    Get-ADObject -LDAPFilter $filter -SearchBase $DN -SearchScope Subtree -Properties $propertylist
}

function Get-KerberosUnconstrainedDelegationAccounts {
    [CmdletBinding()]
    Param (
        # start the search at this DN. Default is to search all of the domain.
        [string]$DN = (Get-ADDomain).DistinguishedName
    )
    $bitmask = [UserAccountControl]::TRUSTED_FOR_DELEGATION
    $filter = "(userAccountControl:1.2.840.113556.1.4.803:=$bitmask)"
    Get-ADObject -LDAPFilter $filter -SearchBase $DN -SearchScope Subtree -Properties $propertylist
}

function Get-KerberosDelegationAccounts {
    [CmdletBinding()]
    Param (
        # start the search at this DN. Default is to search all of the domain.
        [string]$DN = (Get-ADDomain).DistinguishedName
    )
    $bitmask = [UserAccountControl]::TRUSTED_FOR_DELEGATION -bor [useraccountcontrol]::TRUSTED_TO_AUTH_FOR_DELEGATION
    $filter = "(userAccountControl:1.2.840.113556.1.4.803:=$bitmask)"
    Get-ADObject -LDAPFilter $filter -SearchBase $DN -SearchScope Subtree -Properties $propertylist
}
