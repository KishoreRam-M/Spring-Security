# 📚 Study Material: Session vs Token Authentication (with JWT)

## ✨ Overview

**Session vs Token Authentication** are two common ways to manage **user authentication** in web applications.

- **What it is**:  
  They are methods for tracking and verifying users after they log in to your system. Sessions store data on the server, while tokens (like JWTs) store data on the client side.

- **Why it matters**:  
  Modern apps must manage user identity securely. Choosing the right approach impacts **scalability**, **security**, and **developer experience**.

- **Where it's used**:  
  - Sessions → Traditional websites (e.g., e-commerce platforms).
  - JWT Tokens → APIs, mobile apps, microservices.

- **When to apply it**:  
  - Use sessions for server-rendered apps needing server-side state.
  - Use tokens for stateless APIs or mobile-first applications.

- **How it works (at a high level)**:  
  - **Session**: Client stores a session ID in a cookie. Server keeps all session data.
  - **JWT**: Server issues a signed token. Client stores it and sends it with every request. No server storage needed.

---

## 🧠 Key Concepts

### Concept 1: Session-Based Authentication
- Server creates and stores session data after login.
- Client stores only the **session ID** in a cookie.
- Server uses this ID to retrieve the user's session on every request.

### Concept 2: Token-Based Authentication (JWT)
- After login, server generates a **signed JWT token** with user details (called claims).
- Client stores this token (typically in `localStorage` or `sessionStorage`) and sends it in an `Authorization` header.
- Server verifies the token without needing to store any session data.

### Concept 3: JWT Claims
- Claims are **key-value pairs** inside a JWT payload.
- Types of claims:
  - `sub`: Subject (user identity)
  - `exp`: Expiration
  - `iat`: Issued at
  - `roles`, `permissions`: Custom claims for authorization

---

## 🛠️ Examples / Use Cases

### 🔐 Session Example (Java Spring Boot)
```java
// Spring uses HttpSession
session.setAttribute("userId", user.getId());
````

### 🔐 JWT Example (Java Spring Boot)

```java
// Create JWT Token
String jwt = Jwts.builder()
    .setSubject(user.getUsername())
    .claim("roles", user.getRoles())
    .setIssuedAt(new Date())
    .setExpiration(new Date(System.currentTimeMillis() + 3600000))
    .signWith(SignatureAlgorithm.HS256, secretKey)
    .compact();
```

### 📱 Use Cases

* **Session**: Shopping cart in traditional websites.
* **JWT**: Mobile banking app, RESTful APIs, microservices with no centralized session storage.

---

## 📈 Diagrams / Visual Aids

```
+--------+        Login        +------------+         Set session ID cookie
| Client |  ---------------->  |  Server    |  -------------------------------->
+--------+                     +------------+                               
                                    |
                            [ Stores session data ]

Session Request Flow:
+--------+        Request        +------------+   (Looks up session by ID)
| Client |  ----------------->   |  Server    |
|        | (Sends cookie)        |            |
+--------+                       +------------+


JWT Request Flow:
+--------+        Login        +------------+
| Client |  ---------------->  |  Server    |
+--------+                     +------------+
                                  |
                           [ Issues signed JWT ]
                                  |
+--------+  <-- Authorization <--+  
| Client |                       |
+--------+  --> Token in Header ->+ Server verifies & serves
```

---

## ❓ FAQ / Common Confusions

**Q: Why not just store everything in cookies instead of sessions?**
A: Cookies are exposed to the client, making them vulnerable. Sessions store sensitive data securely on the server.

**Q: Can JWT be invalidated before it expires?**
A: Not easily, unless you maintain a **token blacklist**.

**Q: Is JWT safer than sessions?**
A: Not inherently. JWTs are stateless but vulnerable to **XSS** if stored improperly. Sessions can be vulnerable to **CSRF**.

**Q: Which is easier to scale?**
A: JWTs, because they don't require server-side memory or databases to store user sessions.

---

## 🧪 Practice Questions

1. **MCQ**: Which method stores user state on the client?

   * A. Session
   * B. JWT ✅
   * C. Cookies only
   * D. None

2. **Short Answer**: What is the main risk of storing JWTs in localStorage?

3. **MCQ**: Which of the following claims is used to identify the token's intended recipient?

   * A. `sub`
   * B. `exp`
   * C. `aud` ✅
   * D. `iat`

4. **Code**: Write a Spring Boot code snippet that validates a JWT.

5. **Scenario**: You're building a mobile app that communicates with an API. Which authentication method would you choose and why?

---

## 🔗 Further Reading

* [GeeksforGeeks - JWT](https://www.geeksforgeeks.org/json-web-token-jwt/)
* [JWT.io - Debugger & Guide](https://jwt.io)
* [Spring Security Docs](https://docs.spring.io/spring-security/reference/)
* [YouTube Playlist - JWT with Spring Boot](https://www.youtube.com/results?search_query=jwt+spring+boot)

---

## 📝 Summary

* 🔐 **Sessions** store data on the server; **JWTs** store data on the client.
* 💾 **Session ID** is stored in a cookie; JWT is stored as a full token.
* 🌐 **JWT** is better for stateless APIs, mobile apps, and microservices.
* 🚨 JWTs must be secured against **XSS**; Sessions against **CSRF**.
* 🧠 JWTs contain **claims** like `sub`, `iat`, `exp`, `roles`.
* ⚙️ JWT authentication is scalable and fast since it’s stateless.
* 🔁 Sessions are easy to revoke server-side; JWTs require more control mechanisms.
