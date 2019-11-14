# dkim-verify
Verify the most recent **DKIM-Signature** header on an email and identify any points of failure.

## Important Bulletin
As the _usage_ section below states, the nature of this module involves a lot of very change-sensitive **hashing algorithms**.

This means that if, for any reason whatsoever, a _single byte_ of the email being analyzed is changed or altered from the original, the DKIM check **will FAIL**.

Please do everything you can to run this script on a raw version of the email that's _as close as possible_ to the raw email file as you can get.

## TODO
+ [X] Finish the tool.
+ [X] Better script commentation.
+ [X] Add **dependency checks** for the tools used, and issue a notice that they're _REQUIRED_ before running the tool.
+ [ ] Add special-case interpretations, in close accordance with RFC 6367 (such as the **l** body length limit).
  + [ ] Add the `l=` interpretation to the script to truncate the body-length used for the _body hash calculation_ section.
  + [ ] Consider newly-added DKIM PKI that's been added as of **September 2018** in **RFC 8463** (key algorithm `k=ed25519`).

## Usage
```
USAGE: ./dkim-verify.sh email-file [OPTIONS]
  Verify the validity of the most recent DKIM-Signature header
  on a raw email message, and if there are errors, output them.

OPTIONS:
    -n              Do not use colors in the output.
    --get-domain    Used to get the domain from the signature.

NOTES:
 + The '--get-domain' parameter is typically used by the DMARC
 -- script when checking for alignment, but can be used manually.
 + Since the nature of this script involves hashing algorithms,
 -- very slight changes in a copy/paste of an email could result
 -- in the script reporting a failed hash. To prevent this, it's
 -- best to use the original email file, if possible.

```

## Sample Bash Output
![Picture of Sample dkim-verify.sh Script Output](https://raw.githubusercontent.com/NotsoanoNimus/email-security-toolkit/master/docs/images/dkim_working.png)
