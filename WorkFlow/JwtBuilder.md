## 🔐 JWT Generation with `Jwts.builder()`

You're using this to create a **JWT token** after login — something like:

📥 User logs in → ✅ Authenticated → 🛠️ JWT generated → 🔐 Token sent to client (Postman, browser, mobile app)

---

### ✅ Full Code for Reference:

```java
public static String generateToken(Authentication authentication) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("email", authentication.getName());

    return Jwts.builder()
            .setClaims(claims)
            .setSubject(authentication.getName())
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 86400000)) // 1 day
            .signWith(SECRET_KEY)
            .compact();
}
```

---

## 🔍 Line-by-Line Explanation

| 🧱 Code Line                                                      | 🔎 What It Means                                                                               |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `Map<String, Object> claims = new HashMap<>();`                   | You’re creating **extra data (custom payload)** to add into the token (e.g., email, role, ID). |
| `claims.put("email", authentication.getName());`                  | Adding user's email (or username) as a **claim** (you can also add roles, etc.).               |
| `Jwts.builder()`                                                  | Starts **building the JWT token**. Think of it like `StringBuilder` for tokens.                |
| `.setClaims(claims)`                                              | Adds the custom data (payload). This is optional but helpful.                                  |
| `.setSubject(authentication.getName())`                           | The **main subject** (usually the username/email) — like the "identity" of the token.          |
| `.setIssuedAt(new Date())`                                        | Marks the **issue time** of the token. Useful for tracking.                                    |
| `.setExpiration(new Date(System.currentTimeMillis() + 86400000))` | Token expiry time — here, it’s **1 day (24h)** from now.                                       |
| `.signWith(SECRET_KEY)`                                           | **Signs** the token using a secret key — this prevents tampering.                              |
| `.compact();`                                                     | 🏁 Final step — it **generates the complete JWT string** you return to the user.               |

---

## 🧠 Real-Time Example: Login Flow

```bash
# User sends login credentials from Postman
POST /login
{
  "email": "batman@dc.com",
  "password": "iAmDarkKnight"
}

# Server authenticates → Calls generateToken() → Returns token:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

---

## 🔑 JWT Token Has 3 Parts:

1. **Header** – Algorithm, token type
2. **Payload (Claims)** – Your data (email, roles, etc.)
3. **Signature** – Ensures it wasn't changed (via `SECRET_KEY`)
