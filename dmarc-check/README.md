# dmarc-verify
Verify the DMARC pass/fail status of a raw email and explain the action taken as specified by the DMARC record.

This script has dependencies on the **spf-verify.sh** and **dkim-verify.sh** scripts to check the PASS/FAIL state of each for the raw email.

## TODO
+ [ ] More "in the wild" tests and QA for the script.
+ [ ] Finish the spf-verify module and integrate it.
+ [X] Add a dependency check as needed to the script (will investigate this later).
+ [X] ~~Review the hastily-written code for efficiency's sake.~~ _November 14th, 2019_: Looks good so far. :)

## Usage
```
USAGE: ./dmarc-check.sh email-file [OPTIONS]
  Verify the DMARC pass/fail status of a raw email and explain
  the action taken as specified by the DMARC record.

OPTIONS:
  -v             Be verbose in output about the DMARC record, and about
                  the particulars of the email's alignment.
  -a             Include outputs from both the DKIM and SPF verification.
  -d             Show DKIM verification output.
  -s             Show SPF verification output.
  -n             Do not use colors in the output for the script.

NOTES:
  This script depends on "dkim-verify.sh", another script designed
   to validate DKIM-Signature headers, and "spf-verify.sh" to verify
   SPF sender authentication.

  These can be predefined in two variables respectively with "export":
    DKIM_VERIFY and SPF_VERIFY
  Otherwise the script will search for the scripts in the same directory.
  And lastly, in two directories: ../dkim-verify/ and ../spf-verify/,
   which correspond to the structure of the email-security-toolkit project.

```

## Sample Bash Output
```
[notso@anonymous dmarc-check]$ ./dmarc-check.sh purpfail.eml -v
Extracted Header-From Domain: thestraightpath.email
DMARC Record: v=DMARC1;p=reject;sp=reject;pct=100;adkim=s;aspf=s;ri=86400;fo=1;rua=mailto:postmaster@thestraightpath.email;ruf=mailto:postmaster@thestraightpath.email
Policy                         : reject
Subdomain Policy               : reject
Percentage of Mail Affected    : 100
DKIM Classification (ADKIM)    : s (strict mode; DKIM-Signature d= tag CANNOT be a subdomain of the header-from domain)
SPF Classification (ASPF)      : s (strict mode; Envelope-From CANNOT be a subdomain of the header-from domain)
Reporting Policy               : 1
	0 - (DEFAULT) Generate report to the sending MTA if all underlying checks failed.
	1 - Generate a report to the sending MTA if any underlying check failed.
	d - Generate a report if DKIM checks fail.
	s - Generate a report if SPF checks fail.
Reporting Format               : afrf
Reporting Interval             : 86400
Mail Reports Address (RUA)     : postmaster@thestraightpath.email
Failure Reports Address (RUF)  : postmaster@thestraightpath.email

DKIM  :   FAIL and ALIGNMENT (the authentication method failed despite the domain name alignment with the ASPF/ADKIM policy)
SPF   :   FAIL and MISALIGNMENT (the authentication method failed and the domain name doesn't align with the ASPF/ADKIM policy)
DMARC :   FAIL
 `---> DMARC will need at least one PASS-and-ALIGNMENT to pass.
 `---> Aggregate and Failure reports are generated for these failures respectively to the RUA and RUF addresses above, as defined.
 `---> Based on the DMARC policy, receiving MTAs that are checking for DMARC will reject 100% of failed emails as they are checked.

```
