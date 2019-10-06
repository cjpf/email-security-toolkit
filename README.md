# Email Security Toolkit
Everything a consummate administrator, developer, or otherwise security-minded individual should ever need for troubleshooting their email issues.

Scripts will be added over time as they are drafted. **READMEs** can be found in each directory, for each tool, describing script parameters and other relevant information.

Future implementations tentatively include the following translations of each Bash Shell script after initial completion of the library (provided the functionality is available in the target language):
+ PowerShell
+ Perl
+ Python
+ **?** C(++)
+ **?** Java
+ ~~JavaScript (ReactJS, interactive)~~ This has been scrapped as of 2019-10-05, since JS doesn't quite provide any basic networking functionality beyond simple HTTP(S) requests, for good reason. Not interested in making a NodeJS or other JS-based handling server.

# Ideas to Implement
This section will host a checklist of script ideas for tools to add later, whether by suggestion, request, or brainstorming. Items are checked as the sub-project is considered in a "working" state, but of course even the checked projects will likely be revisited and updated as bugs are discovered.

- [ ] _email-toolkit_ - A "_master_" script to use all of the other tools below. This is just an idea right now but will help with creating a "library" file with lots of common routines/functions that can be sourced (`. misc/master.sh`) into other tools.

- [X] _quick-dns_ - Display quick information about a domain's email security/authentication standards in place, and/or provide a quick check against a predefined list of popular DNSBLs.
- [ ] _spf-verify_ - Return raw IPv4/6 ranges for a given domain using their SPF record, or perform a simulated SPF check with a given IP address and SMTP Envelope-From (_MAIL FROM_). Also, evaluate the general policy of the target domain's SPF record.
- [X] _dkim-verify_ - DKIM verification script. Check for body-hash failures and header signature failures, among other checks.
- [X] _dmarc-check_ - Verify the DMARC pass/fail status of a raw email and explain the action taken as specified by the DMARC record.
  + **NOTE**: The DMARC script _depends_ on the SPF and DKIM scripts included in this library to function properly. Please consult the _dmarc-verify_ folder for the README and more information on the project.
- [ ] _mime-check_ - MIME header checker/analyzer. Checks for malformed MIME headers and also describes a raw email's MIME header formatting.
- [ ] _received-trace_ - Received headers analysis. Show the hops and time for each MTA that passed a message. And yes, _exactly_ like the MXToolbox one but in a terminal.
- [X] _test-ciphers_ - Test the support cipher suites of a target server using OpenSSL. This can be helpful for diagnosing TLS/SSL issues.

## General Implementations (commonalities)
Each script will need to follow a certain combined standard to meet the portability requirements across different versions of the same operating systems. Here's a list of standards to maintain/back-fill for each tool (can be expanded later as the project grows):
+ _Fault Tolerance_ - All non-default commands need to be checked and double-checked for operability in the way they are used on the host system. Since one person's testing platform can only be so expansive, it can be difficult to determine the support for certain actions across the thousands of available variants. One example would be to ensure that _dig_ is installed, and if not, attempt to fall back onto a tool like _nslookup_. If neither are supported, inform that at least one is required and exit cleanly.

## Secondary Scripts
These scripts will be purposed strictly for constructing quick-setup MTA environments like a Postfix/Dovecot rollout with simple Unix-password SASL authentication and SMTP over TLS operation. They will also include tools for Postfix and other _open-source_ email-based software, like SpamAssassin rule generators.

For now, this section is simply an idea and may be handed off to its own repository. However, it stays here as it's relevant to the topic of _email_ in general.
