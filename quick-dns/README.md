# quick-dns
A script written to quickly gather email information about a certain domain. Supports the following **checks**:
+ Nameserver lookup and verification.
+ SPF lookup.
+ DMARC lookup.
+ MX-record lookup.
+ Barracuda RBL check against for the A-record of the domain (_the hosting web server_) and the MX-record(s).

## TODO
Nothing to do at this time.

## Sample Bash Output
```
[notso@anonymous quick-dns]$ ./quick-dns.sh -N thestraightpath.email charliejuliet.net
################################################################################
Checking DNS information for thestraightpath.email...
Primary Nameserver: ns11.domaincontrol.com.
SPF Record: "v=spf1 +a:maintain.thestraightpath.email -all"
DMARC Record: "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; ri=86400; fo=1; rua=mailto:postmaster@thestraightpath.email; ruf=mailto:postmaster@thestraightpath.email"
MX Record(s):
        5 maintain.thestraightpath.email.       (Resolved IP: 142.93.49.168)


Attempting A-record RBL check...
Checking Barracuda RBL for the web server IP address (167.99.225.207)... [NOT LISTED]

Attempting MX-record RBL check...
Checking Barracuda RBL for the mail server IP address (142.93.49.168)... [NOT LISTED]


################################################################################
Checking DNS information for charliejuliet.net...
Primary Nameserver: ns18.domaincontrol.com.
SPF Record: "v=spf1 include:_spf.protonmail.ch include:charliejuliet.net mx ~all"
DMARC Record: "v=DMARC1; p=none; rua=mailto:cjpf@charliejuliet.net"
MX Record(s):
        1 mail.charliejuliet.net.       (Resolved IP: 165.227.191.80)


Attempting A-record RBL check...
Checking Barracuda RBL for the web server IP address (23.239.17.132)... [NOT LISTED]

Attempting MX-record RBL check...
Checking Barracuda RBL for the mail server IP address (165.227.191.80)... [NOT LISTED]


[notso@anonymous quick-dns]$
```
