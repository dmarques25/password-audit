# password-audit

**Usage**

Password Audit is a tool for finding user passwords that have their hashes already compromised in the wild, and if stolen, can lead to a quick account compromise. The goal is to audit and remediate weak or compromised credentials.

The tool will extract the NTDS database from Active Directory, as long as the running user has domain admin rights.

The tool will then compare each NTLM hash with the database stored on https://ntlm.pw/ and report if it’s vulnerable or not, taking into consideration the request limitations imposed, so if there’s a huge number of users it will take some time to complete, but it will report the waiting periods.
If this is carried out as part of an audit, it is recommended not to carry out this second phase from the company's public IP address in order to limit any risk of reverse resolution.

The tool has 4 different options:

1 – Only extract NTDS database

2 – Only audit NTML hashes from a previous extract

3 – Extract and audit NTLM hashes

4 – Extract / Audit NTLM hashes and request Password Reset

After running the audit, and do whatever actions needed, delete all the generated data, specially the NTDS database and text files with hashes and passwords to avoid any possible compromise.

 
**Disclaimer**

Password Audit is intended exclusively for research, education, and authorized testing. The tool should not be used for any other purpose and always be used according to existing laws.
