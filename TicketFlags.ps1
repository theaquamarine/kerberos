# https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
# https://tools.ietf.org/html/rfc4120
# https://tools.ietf.org/html/rfc8062
# https://github.com/dotnet/Kerberos.NET/blob/0b83e6b2e4183e17daece5b3cf12187a929b1771/Kerberos.NET/Entities/Krb/TicketFlags.cs
# https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-kerb_ticket_cache_info
[flags()] enum TicketFlags { #left shift = 31-$bitnumber
    None = 0
    Reserved = 1 -shl 31 #0
    Forwardable = 1 -shl 30 #1
    Forwarded = 1 -shl 29 #2
    Proxiable = 1 -shl 28 #3
    Proxy = 1 -shl 27 #4
    MayPostDate = 1 -shl 26 #5
    PostDated = 1 -shl 25 #6
    Invalid = 1 -shl 24 #7
    Renewable = 1 -shl 23 #8
    Initial = 1 -shl 22 #8
    PreAuthenticated = 1 -shl 21 #10
    HardwareAuthentication = 1 -shl 20 #11
    TransitPolicyChecked = 1 -shl 19 #12
    OkAsDelegate = 1 -shl 18 #13
    # RequestAnonymous = 1 -shl 17 #14 should never appear, only in drafts of 6112? https://datatracker.ietf.org/doc/html/draft-ietf-krb-wg-anon-03
    Canonicalize = 1 -shl 16 #15
    Anonymous = 1 -shl 15 #16 https://tools.ietf.org/html/rfc8062
    #17 unused
    #18 unused
    #19 unused
    #20 unused
    #21 unused
    #22 unused
    #23 unused
    #24 unused
    #25 unused
    DisableTransitCheck = 1 -shl 5 #26
    RenewableOk = 1 -shl 4 #27
    EncTktInSkey = 1 -shl 3 #28
    #29 unused
    Renew = 1 -shl 1 #30
    Validate = 1 -shl 0 #31
} # enum TicketFlags
