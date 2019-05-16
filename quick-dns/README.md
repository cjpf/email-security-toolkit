# quick-dns
A script written to quickly gather email information about a certain domain. Supports the following **checks**:
+ Nameserver lookup and verification.
+ SPF lookup.
+ DMARC lookup.
+ MX-record lookup.
+ RBL check against for the A-record of the domain (_the hosting web server_) and the MX-record(s).

## TODO
+ Add reverse-DNS lookup to both the A-record and the MX-record hosts. Warn the user if there are hosts without a valid PTR record.
+ For RBL lookups, many of these providers use specific codes for the reason of the block. Maybe send this output to the user for more info. For example, see https://spfbl.net/en/dnsbl/.
+ Complete IPv6 support.

## Sample Bash Output
```
[notso@anonymous quick-dns]$ ./quick-dns.sh -N thestraightpath.email charliejuliet.net
################################################################################
Checking DNS information for thestraightpath.email...
Primary Nameserver: ns11.domaincontrol.com.
SPF Record: "v=spf1 +a:maintain.thestraightpath.email -all"
DMARC Record: "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; ri=86400; fo=1; rua=mailto:postmaster@thestraightpath.email; ruf=mailto:pos
tmaster@thestraightpath.email"
MX Record(s):
        5 maintain.thestraightpath.email.       (Resolved IP: 142.93.49.168)


Attempting A-record RBL check for 167.99.225.207...
Checking "Barracuda RBL"                                  : [NOT LISTED]

Attempting MX-record RBL check...
  --====================--   142.93.49.168   --====================--  
Checking "Barracuda RBL"                                  : [NOT LISTED]
Checking "SORBS Spam"                                     : [NOT LISTED]
Checking "UCEPROTECTL1"                                   : [NOT LISTED]
Checking "SpamCop"                                        : [NOT LISTED]
Checking "SpamRats NoPTR (no-PTR-record spammers)"        : [NOT LISTED]
Checking "SpamRats DYNA (suspicious PTR records)"         : [NOT LISTED]
Checking "MegaRBL"                                        : [NOT LISTED]
Checking "Spamhaus ZEN"                                   : [NOT LISTED]
Checking "SPFBL"                                          : [LISTED]
 ----> Given Reason (if any): "https://matrix.spfbl.net/142.93.49.168"
Checking "LASHBACK"                                       : [NOT LISTED]
Checking "WPBL"                                           : [NOT LISTED]
Checking "Composite Blocking List (CBL)"                  : [NOT LISTED]


################################################################################
Checking DNS information for charliejuliet.net...
Primary Nameserver: ns18.domaincontrol.com.
SPF Record: "v=spf1 include:_spf.protonmail.ch include:charliejuliet.net mx ip4:23.239.17.132 ~all"
DMARC Record: "v=DMARC1; p=none; rua=mailto:cjpf@charliejuliet.net"
MX Record(s):
        1 mail.charliejuliet.net.       (Resolved IP: 165.227.191.80)


Attempting A-record RBL check for 23.239.17.132...
Checking "Barracuda RBL"                                  : [NOT LISTED]

Attempting MX-record RBL check...
  --====================--   165.227.191.80   --====================--  
Checking "Barracuda RBL"                                  : [NOT LISTED]
Checking "SORBS Spam"                                     : [NOT LISTED]
Checking "UCEPROTECTL1"                                   : [NOT LISTED]
Checking "SpamCop"                                        : [NOT LISTED]
Checking "SpamRats NoPTR (no-PTR-record spammers)"        : [NOT LISTED]
Checking "SpamRats DYNA (suspicious PTR records)"         : [NOT LISTED]
Checking "MegaRBL"                                        : [NOT LISTED]
Checking "Spamhaus ZEN"                                   : [NOT LISTED]
Checking "SPFBL"                                          : [LISTED]
 ----> Given Reason (if any): "https://matrix.spfbl.net/165.227.191.80"
Checking "LASHBACK"                                       : [NOT LISTED]
Checking "WPBL"                                           : [NOT LISTED]
Checking "Composite Blocking List (CBL)"                  : [NOT LISTED]


[notso@anonymous quick-dns]$
```
