# OWASP Top 10 Vulnerabilities - Security Analysis

## Table of Contents
1. [Broken Access Control](#1-broken-access-control)
2. [Cryptographic Failures](#2-cryptographic-failures)
3. [Injection](#3-injection)
4. [Insecure Design](#4-insecure-design)
5. [Software and Data Integrity Failures](#5-software-and-data-integrity-failures)
6. [Server-Side Request Forgery (SSRF)](#6-server-side-request-forgery-ssrf)
7. [Identification and Authentication Failures](#7-identification-and-authentication-failures)

---

## 1. Broken Access Control

**OWASP Reference**: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

### Example 1: JavaScript (Express.js)

**Vulnerability Identified**: Missing Authorization Check

**The Problem**:
The code allows ANY authenticated user to access ANY user's profile just by changing the `userId` parameter in the URL. It's like having a hotel where any guest can access any room just by knowing the room number—there's no check to verify if the guest actually has a key to that room.

**Why It's Dangerous**:
- Users can view other users' private information
- Horizontal privilege escalation (User A accessing User B's data)
- No verification that the requester owns or has permission to view the resource

**Secure Version**: See `01_broken_access_control_js.js`

**How the Fix Works**:
- Verifies the authenticated user's session (req.user.id)
- Checks if the requested userId matches the authenticated user's ID
- Only allows users to access their own data (unless they're an admin)
- Returns 403 Forbidden if authorization fails

---

### Example 2: Python (Flask)

**Vulnerability Identified**: Missing Authorization Check

**The Problem**:
Similar to Example 1, but in Python. The endpoint blindly trusts the user_id parameter without verifying if the current user has permission to access that account. Think of it like a bank teller handing over account information to anyone who walks up and says an account number.

**Why It's Dangerous**:
- Direct object reference without access control
- Any user can enumerate and access all user accounts
- Privacy violation and potential data breach

**Secure Version**: See `02_broken_access_control_python.py`

**How the Fix Works**:
- Uses Flask-Login to track authenticated users
- Compares the requested user_id with the current logged-in user's ID
- Implements role-based access control (allows admins to view all accounts)
- Returns 403 error if user tries to access another user's account

---

## 2. Cryptographic Failures

**OWASP Reference**: [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

### Example 3: Java

**Vulnerability Identified**: Using Weak Hashing Algorithm (MD5)

**The Problem**:
MD5 is cryptographically broken and unsuitable for security purposes. It's like using a diary lock on a bank vault—it was never designed for serious security. MD5 is vulnerable to collision attacks and can be cracked in seconds with modern hardware.

**Why It's Dangerous**:
- MD5 hashes can be reversed using rainbow tables
- Collision attacks are practical and easy
- Fast computation makes brute-force attacks trivial
- No salt means identical passwords have identical hashes

**Secure Version**: See `03_cryptographic_failure_java.java`

**How the Fix Works**:
- Uses bcrypt, a purposefully slow hashing algorithm designed for passwords
- Automatically generates and includes a unique salt for each password
- Includes a work factor (cost) that makes brute-forcing impractical
- Industry-standard approach recommended by OWASP
- The slowness is a feature—it makes attacks computationally expensive

---

### Example 4: Python

**Vulnerability Identified**: Using Weak Hashing Algorithm (SHA-1) Without Salt

**The Problem**:
SHA-1 is cryptographically broken and no salt is used. Even if SHA-1 were secure, the lack of salt means identical passwords produce identical hashes. It's like storing everyone's house key as a photograph—anyone with the same key will have an identical photo.

**Why It's Dangerous**:
- SHA-1 collisions have been demonstrated
- Without salt, rainbow table attacks are highly effective
- Fast hashing enables rapid brute-force attempts
- Identical passwords are immediately visible

**Secure Version**: See `04_cryptographic_failure_python.py`

**How the Fix Works**:
- Uses bcrypt (via the bcrypt library)
- Automatically handles salting
- Slow by design to resist brute-force attacks
- Uses `checkpw()` for secure comparison that prevents timing attacks

---

## 3. Injection

**OWASP Reference**: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

### Example 5: Java (SQL Injection)

**Vulnerability Identified**: SQL Injection via String Concatenation

**The Problem**:
User input is directly concatenated into a SQL query without sanitization. It's like having a conversation where you blindly repeat everything someone tells you—if they say "tell everyone I'm the boss," you do it without thinking. An attacker can input: `admin' OR '1'='1` to bypass authentication or `'; DROP TABLE users; --` to delete data.

**Why It's Dangerous**:
- Complete database compromise possible
- Attackers can read, modify, or delete any data
- Can lead to authentication bypass
- May allow command execution on the database server

**Secure Version**: See `05_injection_java.java`

**How the Fix Works**:
- Uses PreparedStatement with parameterized queries
- Database treats user input as pure data, never as SQL code
- Parameters are properly escaped and typed
- Separates SQL logic from data, making injection impossible

---

### Example 6: JavaScript (NoSQL Injection)

**Vulnerability Identified**: NoSQL Injection via Unvalidated Query Parameters

**The Problem**:
Directly using user input in MongoDB queries allows attackers to inject operators. For example, sending `username[$ne]=` can return the first user that doesn't have an empty username, effectively bypassing intended logic. It's like asking "find the person named X" but the attacker changes it to "find any person NOT named X."

**Why It's Dangerous**:
- Authentication bypass
- Unauthorized data access
- Query manipulation to extract unintended data
- Can enumerate all users or data

**Secure Version**: See `06_injection_javascript.js`

**How the Fix Works**:
- Validates that input is actually a string (not an object with operators)
- Sanitizes input to remove MongoDB operators
- Type checking ensures query structure isn't manipulated
- Returns 400 Bad Request if invalid input detected

---

## 4. Insecure Design

**OWASP Reference**: [A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

### Example 7: Python (Flask)

**Vulnerability Identified**: Password Reset Without Verification

**The Problem**:
The password reset mechanism has no verification process—anyone who knows an email address can change that account's password! It's like a locksmith who changes locks based only on someone knowing the address, without verifying ownership. There's no token, no identity verification, and no notification.

**Why It's Dangerous**:
- Complete account takeover by anyone who knows a victim's email
- No authentication required
- No notification to legitimate user
- Fundamentally flawed security model

**Secure Version**: See `07_insecure_design_python.py`

**How the Fix Works**:
- Generates a secure, random, time-limited reset token
- Sends token to the user's verified email address
- Token must be provided to actually reset the password
- Tokens expire after 1 hour
- User is notified via email (deterrent against unauthorized attempts)
- Follows standard password reset flow used by major platforms

---

## 5. Software and Data Integrity Failures

**OWASP Reference**: [A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

### Example 8: HTML/JavaScript

**Vulnerability Identified**: Loading External Resources Without Integrity Checking

**The Problem**:
Loading JavaScript from an external CDN without verifying its integrity. If the CDN is compromised or the script is modified in transit, malicious code executes on your site. It's like accepting food from a delivery service without any tamper-evident seals—you're trusting it hasn't been poisoned along the way.

**Why It's Dangerous**:
- If cdn.example.com is compromised, attackers control your site
- Man-in-the-middle attacks can inject malicious code
- Supply chain attack vector
- No way to detect if the script has been tampered with
- Can steal user data, credentials, or perform actions on behalf of users

**Secure Version**: See `08_integrity_failure.html`

**How the Fix Works**:
- Uses Subresource Integrity (SRI) with a cryptographic hash
- Browser verifies the downloaded file matches the expected hash
- If hashes don't match, the resource is rejected
- Prevents execution of tampered scripts
- Uses crossorigin="anonymous" for proper CORS handling
- Includes a fallback to a local copy if CDN fails

---

## 6. Server-Side Request Forgery (SSRF)

**OWASP Reference**: [A10:2021 – Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

### Example 9: Python

**Vulnerability Identified**: Unvalidated URL Input Leading to SSRF

**The Problem**:
The server makes HTTP requests to any URL provided by the user without validation. An attacker could request internal resources like `http://localhost:8080/admin` or `http://169.254.169.254/latest/meta-data/` (AWS metadata service). It's like giving a stranger your phone and letting them call anyone—including your bank, your boss, or emergency services—pretending to be you.

**Why It's Dangerous**:
- Access to internal services not exposed to the internet
- Can read cloud provider metadata (AWS, Azure credentials)
- Port scanning of internal network
- Bypass firewall restrictions
- Potential remote code execution on internal systems

**Secure Version**: See `09_ssrf_python.py`

**How the Fix Works**:
- Validates that URLs use safe protocols (http/https only)
- Maintains an allowlist of permitted domains
- Blocks access to private IP ranges (localhost, 10.x.x.x, 192.168.x.x, etc.)
- Blocks cloud metadata endpoints
- Returns clear error messages without exposing internal details
- Defense-in-depth approach with multiple validation layers

---

## 7. Identification and Authentication Failures

**OWASP Reference**: [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

### Example 10: Java

**Vulnerability Identified**: Plain Text Password Comparison

**The Problem**:
Passwords are stored in plain text and compared directly using string equality. It's like a bank storing your PIN on a sticky note instead of in a secure vault. If the database is compromised, every password is immediately exposed. Additionally, the `equals()` method is vulnerable to timing attacks.

**Why It's Dangerous**:
- Passwords stored in clear text in the database
- Database breach exposes all credentials immediately
- No protection against timing attacks
- Violates fundamental security principles
- Legal and compliance issues (GDPR, PCI-DSS, etc.)

**Secure Version**: See `10_authentication_failure_java.java`

**How the Fix Works**:
- Never stores plain text passwords in the database
- Uses bcrypt to hash passwords before storage
- `checkpw()` method safely compares hashed passwords
- Resistant to timing attacks
- Even if database is breached, passwords remain protected
- Industry standard approach

---

## Summary of Security Principles Applied

1. **Principle of Least Privilege**: Users should only access resources they own or have explicit permission to access
2. **Defense in Depth**: Multiple layers of validation and security controls
3. **Secure by Default**: Use secure libraries and avoid rolling your own crypto
4. **Input Validation**: Never trust user input; validate and sanitize everything
5. **Separation of Concerns**: Keep SQL/query logic separate from data
6. **Cryptographic Best Practices**: Use modern, proven algorithms with proper parameters
7. **Secure Design**: Build security into the system from the beginning, not as an afterthought

---

## Additional Resources

- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

