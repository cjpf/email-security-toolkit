# quick_dns.sh
A Shell script written to quickly gather information about a certain domain, for the purpose of troubleshooting potential email issues.

Sample output:
```
~ $ ./quick_dns.sh yeethop.xyz
Primary Nameserver: ns70.domaincontrol.com.
SPF Record: "v=spf1 +mx +a:mail.yeethop.xyz -all"
DMARC Record: "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; ri=86400; fo=1; rua=mailto:postmaster@yeethop.xyz; ruf=mailto:postmaster@yeethop.xyz"
MX Record(s):
5 barricade.behemothrp.com. (Resolved IP: 174.138.59.253)

Attempting A-record RBL check...
Checking Barracuda RBL for the web server IP address (167.99.225.207)... [NOT LISTED]                                                              

Attempting MX-record RBL check...
Checking Barracuda RBL for the mail server IP address (174.138.59.253)... [NOT LISTED]
```
