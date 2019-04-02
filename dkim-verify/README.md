# dkim-verify
Verify the most recent DKIM Signature on an email and check for possible points of failure. More options and information will be added when the tool is completed, and furthermore as it develops.

## TODO
+ [X] Finish the tool.
+ [ ] Add **dependency checks** for the tools used, and issue a notice that they're _REQUIRED_ before running the tool.
+ [ ] Add special-case interpretations, in close accordance with RFC 6367 (such as the **l** body length limit).


## Sample Bash Output
![Picture of Sample dkim-verify.sh Script Output](https://raw.githubusercontent.com/ZacharyPuhl/email-security-toolkit/docs/images/dkim_working.png)
