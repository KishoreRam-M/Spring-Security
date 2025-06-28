## ✅ SPRING SECURITY + JWT + WEB SECURITY IN SPRING BOOT

**(Beginner → Advanced Concepts)**

---

### 🔹 1. **Security Basics**

| Concept                                     | Description                                       |
| ------------------------------------------- | ------------------------------------------------- |
| **Authentication vs Authorization**         | Login identity vs access rights                   |
| **Principals & Authorities**                | Who is accessing and what they can do             |
| **UsernamePasswordAuthenticationToken**     | Used for storing username/password auth info      |
| **SecurityContext & SecurityContextHolder** | Holds the current user’s security information     |
| **Role vs Authority**                       | `ROLE_ADMIN` vs `hasAuthority("READ_PRIVILEGES")` |

---

### 🔹 2. **Spring Security Core**

| Concept                                                                  | Description                                             |
| ------------------------------------------------------------------------ | ------------------------------------------------------- |
| `spring-boot-starter-security`                                           | Enables security in Spring Boot apps                    |
| **Default Login Page**                                                   | Provided by Spring Boot                                 |
| **In-Memory Authentication**                                             | `AuthenticationManagerBuilder.inMemoryAuthentication()` |
| **PasswordEncoder**                                                      | Use `BCryptPasswordEncoder` for secure hashes           |
| `UserDetails` & `UserDetailsService`                                     | Load user-specific data for authentication              |
| `AuthenticationManager`                                                  | Authenticates user credentials                          |
| `WebSecurityConfigurerAdapter` (legacy) / `SecurityFilterChain` (modern) | Core configuration                                      |

---

### 🔹 3. **Custom Authentication**

| Concept                          | Description                         |
| -------------------------------- | ----------------------------------- |
| **Custom Login Form**            | With HTML + Spring Security         |
| **Custom UserDetailsService**    | Loads user from DB (e.g., JPA)      |
| **Custom Authentication Filter** | For advanced authentication methods |
| **Remember-Me Authentication**   | Persistent login via cookies        |

---

### 🔹 4. **JWT (JSON Web Token) Security**

| Concept                      | Description                                      |
| ---------------------------- | ------------------------------------------------ |
| What is JWT                  | Compact, stateless token-based authentication    |
| **Structure of JWT**         | Header, Payload, Signature                       |
| **JWT Generation**           | Encode user info and sign it (HS256)             |
| **JWT Validation**           | Verify token and extract user info               |
| **JWT Filter**               | Custom filter to check JWT in headers            |
| **Stateless Authentication** | No session stored on server                      |
| **Refresh Tokens**           | For generating new JWT without logging in again  |
| Libraries:                   | `jjwt`, `java-jwt` (Auth0), or `nimbus-jose-jwt` |

---

### 🔹 5. **Spring Security with JWT (Modern Way)**

| Concept                         | Description                                     |
| ------------------------------- | ----------------------------------------------- |
| `SecurityFilterChain`           | Define your filter chain manually (recommended) |
| `OncePerRequestFilter`          | Add custom JWT filters                          |
| `AuthenticationManagerResolver` | Advanced control over auth management           |
| **CORS + CSRF**                 | Handling frontend calls securely                |

---

### 🔹 6. **Method-Level Security**

| Annotation                                              | Purpose                    |
| ------------------------------------------------------- | -------------------------- |
| `@PreAuthorize("hasRole('ADMIN')")`                     | Before method execution    |
| `@PostAuthorize`                                        | After method execution     |
| `@Secured("ROLE_USER")`                                 | Role-based method security |
| `@EnableGlobalMethodSecurity` / `@EnableMethodSecurity` | Enable method security     |

---

### 🔹 7. **OAuth2 & Social Login**

| Concept                             | Description                        |
| ----------------------------------- | ---------------------------------- |
| **OAuth2 Login**                    | Google, Facebook, GitHub auth      |
| `spring-boot-starter-oauth2-client` | Enable OAuth2 login                |
| `OAuth2User` & `OAuth2UserService`  | Handle user details                |
| `Security.oauth2.client.*`          | Properties for client registration |

---

### 🔹 8. **Session Management & Remember Me**

| Concept             | Description                        |
| ------------------- | ---------------------------------- |
| Session Timeout     | Logout user after inactivity       |
| Concurrent Sessions | Limit number of sessions per user  |
| Remember-Me Cookies | Persistent login                   |
| Logout Handler      | Invalidate session & clean context |

---

### 🔹 9. **CORS & CSRF**

| Concept                                  | Description                                  |
| ---------------------------------------- | -------------------------------------------- |
| **CORS (Cross-Origin Resource Sharing)** | Allow frontend to access backend APIs        |
| **CSRF (Cross-Site Request Forgery)**    | Protect POST requests from malicious scripts |
| When to disable CSRF                     | Only for stateless JWT APIs                  |
| `CorsConfigurationSource`                | Define allowed origins/headers/methods       |

---

### 🔹 10. **Error Handling & Custom Responses**

| Concept                         | Description                              |
| ------------------------------- | ---------------------------------------- |
| Custom AuthenticationEntryPoint | Customize 401 Unauthorized               |
| AccessDeniedHandler             | Customize 403 Forbidden                  |
| Global Exception Handling       | `@ControllerAdvice`, `@ExceptionHandler` |

---

### 🔹 11. **Security for REST APIs**

| Concept                 | Description                             |
| ----------------------- | --------------------------------------- |
| Stateless API Security  | JWT or API key-based                    |
| API Gateway Integration | Secure microservices                    |
| HMAC Signature          | Securing APIs for external integrations |

---

### 🔹 12. **Database Security Concepts**

| Concept                     | Description                            |
| --------------------------- | -------------------------------------- |
| SQL Injection Prevention    | Use JPA or prepared statements         |
| Secure Password Storage     | Use BCrypt with salts                  |
| Account Locking             | Lock after N failed attempts           |
| Logging Suspicious Activity | Unusual IP or user-agent               |
| Encrypted Fields            | Sensitive data like email, phone, etc. |

---

### 🔹 13. **Real-Time Security Awareness**

| Area                              | Focus                                                 |
| --------------------------------- | ----------------------------------------------------- |
| **XSS**                           | Escape HTML & input validation                        |
| **CSRF**                          | Enable CSRF or use JWT wisely                         |
| **Clickjacking**                  | Use `X-Frame-Options` header                          |
| **CSP (Content Security Policy)** | Prevent loading untrusted scripts                     |
| **Security Headers**              | Add headers via `HttpServletResponse` or filter       |
| **HTTPS Only**                    | Enforce TLS in production                             |
| **Rate Limiting**                 | Protect against brute force & abuse (Bucket4j, Redis) |

---

### 🔹 14. **Advanced Authentication Techniques**

| Concept                                     | Description                      |
| ------------------------------------------- | -------------------------------- |
| **Two-Factor Authentication (2FA)**         | OTP-based via SMS/email/auth app |
| **Biometric Auth Integration**              | With OAuth2/OpenID providers     |
| **SSO (Single Sign-On)**                    | Using OAuth2/OpenID Connect/SAML |
| **Token Blacklisting**                      | Invalidate compromised JWTs      |
| **IP Whitelisting / Device Fingerprinting** | Enterprise-grade security        |

---

### 🔹 15. **Security Testing & Audit**

| Area                       | Tool / Practice                          |
| -------------------------- | ---------------------------------------- |
| **Penetration Testing**    | Burp Suite, OWASP ZAP                    |
| **Static Code Analysis**   | SonarQube, PMD                           |
| **Vulnerability Scanning** | OWASP Dependency Check                   |
| **Audit Logging**          | Log login/logout/actions with timestamps |

---

### 🔹 16. **Security Best Practices for Spring Boot**

* Use strong `BCryptPasswordEncoder` with strength ≥ 10
* Never expose JWT secret keys — use **env variables** or **vaults**
* Use **HTTPS in production only**
* Always validate user input on both frontend and backend
* Use **role-based access control** (RBAC)
* Enforce **least privilege access**
* Don’t trust the client (even with JWTs)
