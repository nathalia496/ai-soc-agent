# Consistency & analyst agreement rating worksheet

For each scenario below: read the N runs' hypothesis/next_steps and fill in `Consistency rating` using this scale:

- **1** = contradicts itself across runs
- **2** = mostly consistent, minor wording differences
- **3** = fully consistent core claim

Then, for the single "Analyst agreement" run per scenario: read ONLY that report (not the scenario's runbook answer key) and decide whether the hypothesis matches what actually happened, before opening the runbook to check. Record pass/fail (or 1-5) in `Analyst agreement rating`. Only look at the runbook file named under each scenario after you've written your rating down.

---

## malware_initial_triage

Runbook (answer key - **do not open until after rating**): `run_books/soc1/cases/malware_initial_triage.md`

### Consistency across runs

**Run 1**

- Hypothesis: The system has been compromised by a targeted adversary exploiting vulnerabilities in the user's software dependencies and development tools.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'j.ramirez']
- Next steps:
  - Analyze the hash 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d' for connections to the developer's repository or public knowledge bases
  - Verify the user's credentials and verify the legitimacy of the scheduled task "WindowsUpdateSvc"
  - Perform further analysis on the IP '10.20.5.17' to identify possible connections to known C2 infrastructure
  - Verify the user's activity and interaction with suspicious executables
  - Investigate the developer's repository for any updates or changes that could be related to this incident
  - Run a full scan of the system for any further malware activity
**Run 2**

- Hypothesis: The system administrator is deliberately attempting to mask command and control communication by using a compromised process to interact with the system.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'j.ramirez']
- Next steps:
  - Identify the source and pattern of the scheduled task 'WindowsUpdateSvc'
  - Check system logs for inconsistencies in user privileges and account activities
  - Inquire about the reason for the downloaded unsigned executable file 'update_svc.exe'
  - Perform additional OS layer and network scans for related malicious IP addresses or artifacts
**Run 3**

- Hypothesis: The system has been compromised through the creation of a malicious scheduled task, designed to persist in the system and remain undetected.
- Observables: ['10.20.5.17', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', '185.220.101.47', 'j.ramirez']
- Next steps:
  - Verify the legitimacy of update_svc.exe via reverse engineering or digital forensics analysis
  - Investigate the command and control (C2) communication with 185.220.101.47
  - Scan the system for additional malicious scheduled tasks or processes
  - Review system logs for any modifications or tampering of existing system files and directories
  - Check for any updates or changes to user credentials or access control lists
**Run 4**

- Hypothesis: The system has been compromised by a previously unseen threat actor utilizing scheduled task operations to achieve persistence on the host.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'j.ramirez']
- Next steps:
  - Analyze the malicious executable 'update_svc.exe' for additional details on its content and potential payload
  - Verify the legitimate usage of the Download folder and ensure no similar suspicious activity was noticed in the past
  - Research the known-malicious IP 185.220.101.47 and its association with malicious activities and C2 capabilities
  - Recon the user\u2019s system for any signs of the threat actor\u2019s presence, such as unauthorized software or services
  - Check the system logs for potential signs of stealthy persistence via scheduled task operations
  - Interrogate and inspect a possible copy of the malicious executable or malicious service for additional information
  - Query the threat actor's possible tools and resources in use, such as Tor exits
  - Perform a more thorough investigation into the user\u2019s past behavior to identify any suspicious activities before this incident
  - Collaborate with other teams, such as IT\u2019s department for full scope awareness and additional support
**Run 5**

- Hypothesis: The user J.Ramirez executed an unsigned executable that established a connection to a known Malware C2 server and created a scheduled task for persistence.
- Observables: ['10.20.5.17']
- Next steps:
  - Review the sysinternal logs for process creation dates and times.
  - Analyze traffic to 185.220.101.47:443 for malicious activity.
  - Query the user J.Ramirez about the source of the update_svc.exe executable.

**Consistency rating (1-3):** 1

**Notes:** Root cause differs materially across runs - run 1 claims "vulnerability exploitation in software dependencies" (not supported by any evidence), run 2 claims a deliberate insider admin masking C2 traffic, runs 3-4 attribute it to an external actor using a scheduled task for persistence, and only run 5 matches the ground truth closely (unsigned exe -> C2 -> scheduled task persistence). Ground truth (from the fixture's alert.signal.rule.description): "Unsigned executable 'update_svc.exe' spawned from a user Downloads folder, established an outbound connection to a known-malicious IP, and created a scheduled task for persistence."

### Analyst agreement (representative run: run 1)

**Run 1 (same as above)**

- Hypothesis: The system has been compromised by a targeted adversary exploiting vulnerabilities in the user's software dependencies and development tools.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'j.ramirez']
- Next steps:
  - Analyze the hash 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d' for connections to the developer's repository or public knowledge bases
  - Verify the user's credentials and verify the legitimacy of the scheduled task "WindowsUpdateSvc"
  - Perform further analysis on the IP '10.20.5.17' to identify possible connections to known C2 infrastructure
  - Verify the user's activity and interaction with suspicious executables
  - Investigate the developer's repository for any updates or changes that could be related to this incident
  - Run a full scan of the system for any further malware activity

**Analyst agreement rating (pass/fail or 1-5):** FAIL (1/5)

**Notes:** Run 1's hypothesis centers on "vulnerabilities in software dependencies and development tools" - there is no such evidence in the alert or logs (no dependency/dev-tool content at all). The real story is a downloaded unsigned executable with a C2 callback and a persistence scheduled task, none of which the hypothesis sentence captures, even though the observables list (IPs, hash, user) is technically correct.

---

## suspicious_login_triage

Runbook (answer key - **do not open until after rating**): `run_books/soc1/cases/suspicious_login_triage.md`

### Consistency across runs

**Run 1**

- Hypothesis: The attacker attempted to use a VPN connection to compromise user r.alvarez, potentially for persistence and privilege escalation.
- Observables: ['198.51.100.23', '10.5.0.44', 'Chicago, US', 'Lagos, NG']
- Next steps:
  - Reverse lookup of the VPN gw-01 host to identify potential command and control servers
  - DNS analysis of user r.alvarez to check for suspicious domain lookups
  - Geolocation analysis of 198.51.100.23 to determine its origin
  - Check VPN server logs for suspicious login attempts or activity
**Run 2**

- Hypothesis: User r.alvarez used a VPN to move from a geolocation in Chicago, US to a geolocation in Lagos, NG, compromising the security of their login activity.
- Observables: [['198.51.100.23', '10.5.0.44'], ['Lagos, NG', 'Chicago, US'], 'r.alvarez']
- Next steps:
  - Analyze the VPN logs for suspicious connection attempts
  - Validate the user's travel details to determine the authenticity of the geolocation claims
  - Verify the user's account access permissions and activities
  - Check for any recent changes to the user's software dependencies or development tools
**Run 3**

- Hypothesis: The attack is likely using a fake location to make it harder to track the user's actual location, possibly to gain access to resources restricted by location-based policies.
- Observables: ['198.51.100.23', '10.5.0.1', '10.5.0.44', 'r.alvarez']
- Next steps:
  - Verify the VPN setup and ensure it was not tampered with.
  - Verify user location against external sources such as phone or IP tracking.
  - Check for potential fake IP address generation using software such as Tor or proxy servers.
  - Analyze VPN protocol logs to ensure no logging is being blocked.
  - Verify geolocation data is being properly updated for the user and VPN connection.
**Run 4**

- Hypothesis: The attacker utilized VPN to move from Chicago, US to Lagos, NG within a short time frame, potentially for lateral movement or privilege escalation.
- Observables: ['198.51.100.23']
- Next steps:
  - Verify IP geolocation history for vpn-gw-01 before and after the second successful login
  - Check VPN usage patterns and logs for indicative activity similar to the first attempt
  - Evaluate the user's access roles and permissions given the suspicious login behavior
  - Perform thorough analysis on VPN server access logs to potentially uncover additional activity
**Run 5**

- Hypothesis: The actor moved the user's login location to a different country, using the VPN capability, to avoid detection.
- Observables: ['r.alvarez', '10.5.0.44', '198.51.100.23', '198.51.100.23']
- Next steps:
  - Investigate the VPN server's log for any suspicious activity or location assignments
  - Check if the user's device has any VPN apps or configurations
  - Verify if the user's profile has any access restrictions related to international locations
  - Check for any geolocation-related IP address mappings in the VPN server's database

**Consistency rating (1-3):** 2

**Notes:** 4 of 5 runs reference the Chicago-to-Lagos VPN movement in some form (the actual "impossible travel" pattern); run 3 diverges into a "spoofed geolocation to bypass location-based access policy" narrative instead. Core theme (VPN + suspected compromise) is shared, but the specific mechanism varies. Ground truth: "User r.alvarez authenticated from an IP geolocated to a different country than a successful login 6 minutes earlier, with no travel plausible between the two locations."

### Analyst agreement (representative run: run 1)

**Run 1 (same as above)**

- Hypothesis: The attacker attempted to use a VPN connection to compromise user r.alvarez, potentially for persistence and privilege escalation.
- Observables: ['198.51.100.23', '10.5.0.44', 'Chicago, US', 'Lagos, NG']
- Next steps:
  - Reverse lookup of the VPN gw-01 host to identify potential command and control servers
  - DNS analysis of user r.alvarez to check for suspicious domain lookups
  - Geolocation analysis of 198.51.100.23 to determine its origin
  - Check VPN server logs for suspicious login attempts or activity

**Analyst agreement rating (pass/fail or 1-5):** 3/5 (partial)

**Notes:** Directionally correct (VPN + suspected compromise) and the observables correctly include both geolocations, but the hypothesis text never states the actual distinguishing anomaly - the impossible-travel timing (two logins 6 minutes apart from geographically incompatible locations) - and instead speculates about "persistence and privilege escalation" that isn't evidenced yet at this triage stage.

---

## malware_deep_analysis

Runbook (answer key - **do not open until after rating**): `run_books/soc2/cases/malware_deep_analysis.md`

### Consistency across runs

**Run 1**

- Hypothesis: The attackers used multi-host malware propagation with lateral movement to infect additional machines, evading initial security controls.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'svc-backup', 'WKSTN-0417', 'SRV-FIN02', 'update_svc.exe', 'svchost.exe']
- Next steps:
  - Investigate the network activity of SRV-FIN02 to identify all incoming and outgoing connections.
  - Analyze the system call traces of WKSTN-0417 and SRV-FIN02 for further evidence of process injection and malware communication.
  - Enumerate the services running on SRV-FIN02 and verify their legitimate use.
  - Verify the security of the SMB admin share on SRV-FIN02 and check for any signs of privilege escalation.
  - Search for other compromised machines connected to the C2 infrastructure at 45.137.21.9:8443.
**Run 2**

- Hypothesis: The adversary used SMB-based lateral movement, process injection, and a C2 beacon to compromise multiple hosts.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'svc-backup']
- Next steps:
  - Re-create the network stream to confirm SMB authentication occurred:
  - Investigate the secondary C2 infrastructure (45.137.21.9:8443) for persistent connections or beaconing activity:
  - Analyze the signed C# code to understand the svchost.exe payload:
  - Check for and document any SMB admin shares used to transmit the update_svc.exe payload:
  - Inspect the credentials used to authenticate to SRV-FIN02 to identify potential privilege escalation tactics.
  - Evaluate the score assigned to T1007 System Service Discovery to determine the likelihood of additional compromised services on the affected hosts.
**Run 3**

- Hypothesis: The attacker used SMB-based lateral movement and process injection to spread the malware from WKSTN-0417 to SRV-FIN02.
- Observables: ['a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', '10.20.5.17', '185.220.101.47', 'svc-backup', 'update_svc.exe', 'svchost.exe']
- Next steps:
  - Re-analyze the SMB authentication logs to determine if any other lateral movement occurred between WKSTN-0417 and SRV-FIN02.
  - Check for any other services or processes using svchost.exe on SRV-FIN02.
  - Verify the IP address of the secondary C2 infrastructure used by SRV-FIN02 for outgoing beaconing.
  - Investigate the services and dependencies of update_svc.exe for any potential vulnerabilities.
**Run 4**: FAILED - IntegrationError: Ollama report failed validation: Ollama report is missing required key(s): ['next_steps']. Got keys: ['timeline', 'observables', 'hypothesis']
**Run 5**

- Hypothesis: The attackers used SMB-based lateral movement to move from WKSTN-0417 to SRV-FIN02, creating a new endpoint that leverages compromised software dependencies and development tools.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'svc-backup']
- Next steps:
  - Investigate the use of SMB auth for elevated privileges
  - Examine the files on SRV-FIN02 for any other potentially compromised executables
  - Follow the chain of trust for update_svc.exe to understand its origin and potential further propagation
  - Analyze the IP and C2 connection for any signs of lateral movement or additional endpoints

**Consistency rating (1-3):** 2

**Notes:** Runs 1, 2, 3, and 5 (run 4 failed schema validation) all agree on the core claim - SMB-based lateral movement from WKSTN-0417 to SRV-FIN02 - with runs 2 and 3 matching the ground truth almost exactly (SMB lateral movement + process injection). Run 5 adds an unsupported "compromised software dependencies and development tools" detail not in the evidence (same hallucination pattern seen in malware_initial_triage run 1); run 1 is vaguer but not contradictory. Ground truth: "The file hash from the eval-malware-initial-triage case (update_svc.exe) was observed executing on a second host (SRV-FIN02) after SMB-based lateral movement from WKSTN-0417, with process injection and C2 beaconing to multiple IPs."

### Analyst agreement (representative run: run 1)

**Run 1 (same as above)**

- Hypothesis: The attackers used multi-host malware propagation with lateral movement to infect additional machines, evading initial security controls.
- Observables: ['10.20.5.17', '185.220.101.47', 'a5f2a86a936ef80a0e6c19adff6105c845aeacff0fb725bbee32eeb53cf4c9d', 'svc-backup', 'WKSTN-0417', 'SRV-FIN02', 'update_svc.exe', 'svchost.exe']
- Next steps:
  - Investigate the network activity of SRV-FIN02 to identify all incoming and outgoing connections.
  - Analyze the system call traces of WKSTN-0417 and SRV-FIN02 for further evidence of process injection and malware communication.
  - Enumerate the services running on SRV-FIN02 and verify their legitimate use.
  - Verify the security of the SMB admin share on SRV-FIN02 and check for any signs of privilege escalation.
  - Search for other compromised machines connected to the C2 infrastructure at 45.137.21.9:8443.

**Analyst agreement rating (pass/fail or 1-5):** 4/5 (pass)

**Notes:** The hypothesis sentence itself is generic ("multi-host propagation with lateral movement"), but the observables and next_steps correctly and specifically name both hosts, the SMB admin share, and the exact secondary C2 address (45.137.21.9:8443) - information an analyst would actually act on, even though the one-line hypothesis undersells how specific the underlying finding is.

---

## suspicious_login_investigation

Runbook (answer key - **do not open until after rating**): `run_books/soc2/cases/suspicious_login_investigation.md`

### Consistency across runs

**Run 1**

- Hypothesis: RAlvarez's account was compromised through a combination of MFA device registration, bulk downloads, and unauthorized access attempts, suggesting a targeted attack.
- Observables: ['198.51.100.23', '10.5.0.1', 'r.alvarez']
- Next steps:
  - Analyze MFA device registration patterns
  - Identify all downloaded and accessed files from Finance-Shared SharePoint site
  - Verify VPN logs for VPN connection anomalies
  - Check for suspicious changes in RAlvarez's profile and account settings
  - Collaborate with Finance-Shared team to review shared files and access metrics
**Run 2**

- Hypothesis: The user's account has been compromised, with the attacker using a new, unfamiliar MFA device to gain initially access, followed by bulk downloads of financial data and attempts to escalate privileges.
- Observables: ['198.51.100.23', '10.5.0.1', 'r.alvarez']
- Next steps:
  - Analyze the MFA device used to determine if it belongs to the user or was compromised by the attacker.
  - Verify the legitimacy of the bulk downloaded files and determine if they were accessed by the attacker.
  - Review access logs and incident response policies to determine the root cause and scope of the compromise.
**Run 3**

- Hypothesis: The user's account has been compromised, likely through the use of stolen or forged MFA devices or credentials.
- Observables: ['198.51.100.23', '10.5.0.1', 'r.alvarez']
- Next steps:
  - Verify the authenticity of the MFA device and the legitimacy of the login history.
  - Investigate the SharePoint downloads and determine if any sensitive data has been exfiltrated.
  - Check the VPN logs for any unusual activity and verify the user's VPN connection.
  - Notify the user and request a password reset and verify their login credentials.
**Run 4**: FAILED - IntegrationError: Ollama report failed validation: Ollama report is missing required key(s): ['observables']. Got keys: ['timeline', ' observables', 'hypothesis', 'next_steps']
**Run 5**

- Hypothesis: The user's session was compromised through a multi-factor authentication attack, allowing an attacker to gain privileged access to the system.
- Observables: ['198.51.100.23', '10.5.0.1', 'r.alvarez', 'vpn-gw-01']
- Next steps:
  - Investigate the VPN connection logs for suspicious activity prior to the user's login
  - Verify the financial files downloaded from the SharePoint site to determine if any unauthorized changes were made
  - Check the system audit logs for any other suspicious access attempts by r.alvarez before or after the compromised session
  - Run a full scan of the user's device and network connection for malware or other persistence threats

**Consistency rating (1-3):** 2

**Notes:** Runs 1, 2, 3, and 5 (run 4 failed schema validation) all converge on "account compromised, involving the MFA device and a privilege-escalation-flavored action," with runs 1 and 2 matching the ground truth closely (MFA registration + bulk download + unauthorized/escalation attempt). Run 3 frames the new MFA device as the *initial compromise vector* rather than a *post-compromise* action, and run 5 incorrectly states the attacker "gained" privileged access when the payroll console attempt was actually denied. Ground truth: "Following the impossible-travel login..., a new MFA device was registered, a bulk download occurred from the finance SharePoint site, and an access attempt was made to the payroll admin console... all inconsistent with the user's normal behavior baseline."

### Analyst agreement (representative run: run 1)

**Run 1 (same as above)**

- Hypothesis: RAlvarez's account was compromised through a combination of MFA device registration, bulk downloads, and unauthorized access attempts, suggesting a targeted attack.
- Observables: ['198.51.100.23', '10.5.0.1', 'r.alvarez']
- Next steps:
  - Analyze MFA device registration patterns
  - Identify all downloaded and accessed files from Finance-Shared SharePoint site
  - Verify VPN logs for VPN connection anomalies
  - Check for suspicious changes in RAlvarez's profile and account settings
  - Collaborate with Finance-Shared team to review shared files and access metrics

**Analyst agreement rating (pass/fail or 1-5):** 5/5 (pass)

**Notes:** Accurately captures all three distinguishing anomalous actions from the ground truth (new MFA device, bulk SharePoint download, unauthorized/escalation access attempt). Only minor gap: doesn't explicitly tie the hypothesis back to the prior impossible-travel alert as the initial access vector.

---

