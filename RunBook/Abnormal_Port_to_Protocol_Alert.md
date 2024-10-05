
### **Runbook: Abnormal Port-to-Protocol Mapping**

---

### **Alert Overview**:

- **Alert Name**: Abnormal Port-to-Protocol Mapping (Azure Firewall Application Logs)
- **Severity**: Medium
- **Category**: Firewall Denials, Network Misconfigurations, Potential Anomaly
- **Source**: Azure Firewall Logs via AzureDiagnostics
- **Description**: This alert is triggered when traffic is observed using protocols on ports that don't match the standard configurations (e.g., non-HTTP traffic on port 80 or non-HTTPS traffic on port 443). The Azure Firewall has denied this traffic as no rules matched the requests, and the default action was to deny the traffic.

---

### **Purpose of the Alert**:

This alert is designed to track and detect **non-standard port-to-protocol usage** and monitor traffic that is blocked by Azure Firewall due to the absence of matching rules. This helps identify potential misconfigurations, unusual activity, or attempts to bypass security policies.

---

### **How the Alert Works**:

1. **Query Overview**:
   The query looks for **Azure Firewall Application Logs** where traffic requests use **non-standard protocols on ports** like 80 (HTTP) or 443 (HTTPS). The query checks whether the traffic is being denied because there are no firewall rules allowing the traffic.

2. **Key Elements Detected**:
   - **Source IP (`srcip`)**: The IP address from which the traffic originated.
   - **Destination URL (`dsturl`)**: The backend server or URL the traffic is attempting to reach.
   - **Destination Port (`dstport`)**: The port being used for the communication.
   - **Protocol (`protocol`)**: The protocol being used (e.g., HTTP, HTTPS).
   - **Log Message (`msg_s`)**: Detailed information about the traffic and the action taken by the firewall.
   - **Count**: Number of occurrences of this behavior, to detect patterns.

---

### **Key Investigation Steps**:

1. **Run the Query**:
   First, run the KQL query to identify and summarize the traffic that was denied by the firewall:
   
   ```kql
   let startTime = ago(7d);
   let endTime = now();
   AzureDiagnostics
   | where TimeGenerated between (startTime .. endTime)
   | where OperationName == "AzureFirewallApplicationRuleLog"
   | parse msg_s with protocol " request from " srcip ":" srcport " to " dsturl ":" dstport "." *
   | where isnotempty(dstport)
   | extend dstport_int = toint(dstport)
   // Filter out normal HTTP (80) and HTTPS (443) traffic
   | where not ((protocol == "HTTP" and dstport_int == 80) and (protocol == "HTTPS" and dstport_int == 443))
   // Summarize the count of occurrences by protocol, port, srcip, destination, and msg_s
   | summarize Count = count(), any(msg_s) by protocol, dstport_int, srcip, dsturl
   // Sort the summarized result by count of occurrences
   | order by Count desc
   ```
    
   This query will provide an overview of traffic that has been **blocked** by the firewall due to the use of **non-standard protocols on standard ports**.
    
2. **Review the Results**:
    - **Source IP**: Check the IP addresses from which the blocked traffic originated. Are they internal or external IP addresses? Are they recognized systems or users?
    - **Destination URL**: Investigate the destination URL. Is it a legitimate service within your network, or is it an unknown or suspicious domain?
    - **Port and Protocol**: Confirm whether the protocol being used aligns with the expected behavior for the port. For example, HTTP should be on port 80 and HTTPS on port 443. Any deviation should be reviewed.
    - **Count**: Review how many times this mismatch occurred. A high count may indicate persistent attempts, automated traffic, or misconfiguration.

3. **Validate Legitimate Traffic**:
    - **Legitimate Business Need**: Verify if the blocked traffic is necessary for business operations. Some applications may use non-standard ports and require specific firewall rules.
    - **Firewall Configuration**: If the traffic is legitimate but being blocked due to missing firewall rules, you may need to update the firewall configuration to allow the necessary traffic.

4. **Investigate Suspicious Activity**:
    - **Unrecognized Traffic**: If the source IP or destination URL is unrecognized or unexpected, investigate further. This could indicate port scanning, protocol tunneling, or malicious attempts to bypass security controls.
    - **Look for Anomalies**: If the protocol does not match the port (e.g., non-HTTPS traffic over port 443), this could indicate attempts to disguise malicious traffic.

---

### **Response Actions**:

1. **Immediate Response**:
    - **Check if the traffic is legitimate**: If legitimate business services or applications are being blocked, update firewall rules to allow the necessary traffic.
    - **Investigate the source**: If the source IP or destination URL appears suspicious, escalate the investigation to security teams.

2. **Firewall Rule Adjustment**:
    - **Update firewall rules**: If the traffic is deemed legitimate, ensure that the appropriate firewall rules are created to allow the traffic. Document the change for future reference.

3. **Monitor for Recurrence**:
    - **Log monitoring**: Continue monitoring for additional instances of blocked traffic using the same protocols and ports.
    - **Audit and fine-tune rules**: Regularly audit firewall rules to ensure legitimate traffic is allowed and unnecessary services are blocked.

---

### **Conclusion**:

The **Abnormal Port-to-Protocol Alert** is used to detect and investigate instances where traffic using non-standard protocols is being blocked by Azure Firewall. Depending on the results, you can either adjust the firewall rules to allow legitimate traffic or continue blocking suspicious or unnecessary traffic.

- **If the traffic is legitimate**: Create a specific allow rule in the firewall for this traffic.
- **If the traffic is suspicious**: Continue to block the traffic and investigate the source further.

Document all changes to firewall rules and log any suspicious activity for future reference.
