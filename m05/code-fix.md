# OWASP Top 10 - Vulnerable vs Secure Code

## 1. Broken Access Control - Example 1 (JavaScript/Express)

###  VULNERABLE CODE
```javascript
app.get('/profile/:userId', (req, res) => {
    User.findById(req.params.userId, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
```

###  SECURE CODE
```javascript
app.get('/profile/:userId', (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const requestedUserId = req.params.userId;
    const currentUserId = req.user.id;

    if (requestedUserId !== currentUserId && !req.user.isAdmin) {
        return res.status(403).json({ error: 'Access denied' });
    }

    User.findById(requestedUserId, (err, user) => {
        if (err) return res.status(500).json({ error: 'Server error' });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    });
});
```

---

## 2. Broken Access Control - Example 2 (Python/Flask)

###  VULNERABLE CODE
```python
@app.route('/account/<user_id>')
def get_account(user_id):
    user = db.query(User).filter_by(id=user_id).first()
    return jsonify(user.to_dict())
```

###  SECURE CODE
```python
from flask_login import login_required, current_user

@app.route('/account/<user_id>')
@login_required
def get_account(user_id):
    try:
        requested_user_id = int(user_id)
    except ValueError:
        abort(400, description="Invalid user ID")
    
    if current_user.id != requested_user_id and not current_user.has_role('admin'):
        abort(403, description="Access denied")
    
    user = db.query(User).filter_by(id=requested_user_id).first()
    if not user:
        abort(404, description="User not found")
    
    return jsonify(user.to_dict())
```

---

## 3. Cryptographic Failures - Example 1 (Java)

###  VULNERABLE CODE
```java
public String hashPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(password.getBytes());
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary(digest);
}
```

###  SECURE CODE
```java
import org.mindrot.jbcrypt.BCrypt;

public String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt(12));
}

public boolean verifyPassword(String plainPassword, String hashedPassword) {
    return BCrypt.checkpw(plainPassword, hashedPassword);
}
```

---

## 4. Cryptographic Failures - Example 2 (Python)

###  VULNERABLE CODE
```python
import hashlib

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest()
```

###  SECURE CODE
```python
import bcrypt

def hash_password(password):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password_bytes, salt)

def verify_password(password, hashed_password):
    password_bytes = password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password)
```

---

## 5. Injection - SQL Injection (Java)

###  VULNERABLE CODE
```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

###  SECURE CODE
```java
String username = request.getParameter("username");
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, username);
ResultSet rs = pstmt.executeQuery();
```

---

## 6. Injection - NoSQL Injection (JavaScript)

###  VULNERABLE CODE
```javascript
app.get('/user', (req, res) => {
    db.collection('users').findOne({ username: req.query.username }, (err, user) => {
        if (err) throw err;
        res.json(user);
    });
});
```

###  SECURE CODE
```javascript
app.get('/user', (req, res) => {
    const username = req.query.username;
    
    if (!username || typeof username !== 'string') {
        return res.status(400).json({ error: 'Invalid username' });
    }
    
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({ error: 'Invalid username format' });
    }
    
    db.collection('users').findOne(
        { username: String(username) },
        { projection: { password: 0 } },
        (err, user) => {
            if (err) return res.status(500).json({ error: 'Server error' });
            res.json(user || { error: 'User not found' });
        }
    );
});
```

---

## 7. Insecure Design - Password Reset (Python)

###  VULNERABLE CODE
```python
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    user = User.query.filter_by(email=email).first()
    user.password = new_password
    db.session.commit()
    return 'Password reset'
```

###  SECURE CODE
```python
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
mail = Mail(app)

@app.route('/request-password-reset', methods=['POST'])
def request_password_reset():
    email = request.form.get('email', '').strip()
    user = User.query.filter_by(email=email).first()
    
    if user:
        token = serializer.dumps(email, salt='password-reset-salt')
        reset_url = url_for('reset_password_with_token', token=token, _external=True)
        
        msg = Message('Password Reset Request', recipients=[email])
        msg.body = f'Click to reset your password (valid 1 hour): {reset_url}'
        mail.send(msg)
    
    return jsonify({'message': 'If account exists, reset link sent'})

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password_with_token(token):
    new_password = request.form.get('new_password')
    
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    user = User.query.filter_by(email=email).first()
    if user:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
    
    return jsonify({'message': 'Password reset successful'})
```

---

## 8. Software and Data Integrity Failures (HTML)

###  VULNERABLE CODE
```html
<script src="https://cdn.example.com/lib.js"></script>
```

###  SECURE CODE
```html
<script 
    src="https://cdn.example.com/lib.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
    crossorigin="anonymous">
</script>

<!-- Generate hash with: -->
<!-- curl https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A -->
```

---

## 9. Server-Side Request Forgery (Python)

###  VULNERABLE CODE
```python
url = input("Enter URL: ")
response = requests.get(url)
print(response.text)
```

###  SECURE CODE
```python
import requests
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_DOMAINS = ['api.example.com', 'data.example.com']

def is_safe_url(url):
    parsed = urlparse(url)
    
    if parsed.scheme not in ['http', 'https']:
        return False, "Only http/https allowed"
    
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False, "Domain not in allowlist"
    
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False, "Private IPs blocked"
    except:
        return False, "Could not resolve hostname"
    
    return True, None

def fetch_url(url):
    is_safe, error = is_safe_url(url)
    if not is_safe:
        raise ValueError(f"SSRF Protection: {error}")
    
    return requests.get(url, timeout=5, allow_redirects=False)

# Usage
url = input("Enter URL: ")
try:
    response = fetch_url(url)
    print(response.text)
except ValueError as e:
    print(f"Error: {e}")
```

---

## 10. Identification and Authentication Failures (Java)

###  VULNERABLE CODE
```java
if (inputPassword.equals(user.getPassword())) {
    // Login success
}
```

###  SECURE CODE
```java
import org.mindrot.jbcrypt.BCrypt;

// During registration - hash the password
public void registerUser(String username, String password) {
    String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
    user.setPasswordHash(hashedPassword); // Store hash, not plain password
    userRepository.save(user);
}

// During login - verify the password
public boolean authenticate(String inputPassword, User user) {
    return BCrypt.checkpw(inputPassword, user.getPasswordHash());
}
```

---

## Summary of Key Fixes

1. **Broken Access Control**: Add authentication + authorization checks
2. **Cryptographic Failures**: Use bcrypt/Argon2 instead of MD5/SHA-1
3. **SQL Injection**: Use PreparedStatement with parameterized queries
4. **NoSQL Injection**: Validate input types and sanitize data
5. **Insecure Design**: Use secure tokens with expiration for password reset
6. **Integrity Failures**: Add SRI hashes to external resources
7. **SSRF**: Validate URLs with allowlists and block private IPs
8. **Authentication**: Hash passwords with bcrypt, never store plain text