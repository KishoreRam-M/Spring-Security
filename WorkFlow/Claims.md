## 🔍 What is **`Claims`** in JWT?

In JWT (JSON Web Token), a **Claim** is just a **piece of information** about the user or token.
You can think of it like **key-value pairs inside the token**.

---

### 🧠 Think of JWT Like a Passport

A JWT is like a **digital passport** that contains:

* your **name**
* your **email**
* your **role**
* the **issue date**
* and more…

Each of these is a **claim**.

---

### 🔐 Example: JWT Claims

Here’s a sample JWT decoded:

```json
{
  "sub": "user123",
  "email": "john@gmail.com",
  "role": "ADMIN",
  "iat": 1690987212,
  "exp": 1691073612
}
```

In this:

| Key     | Claim Name   | Meaning                                     |
| ------- | ------------ | ------------------------------------------- |
| `sub`   | Subject      | The main identifier (like user ID or email) |
| `email` | Custom claim | Email of the user                           |
| `role`  | Custom claim | Role (USER, ADMIN)                          |
| `iat`   | Issued At    | When the token was created                  |
| `exp`   | Expiration   | When the token will expire                  |

---

### ✅ In Your Code:

You use this:

```java
claims.put("email", authentication.getName());
```

This adds a **custom claim** called `"email"` into the token.

Later you extract it using:

```java
Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

String email = (String) claims.get("email");
```

---

## 🔑 Types of Claims

JWT has 3 types of claims:

| Type                  | Example                    | Meaning                  |
| --------------------- | -------------------------- | ------------------------ |
| **Registered claims** | `sub`, `iat`, `exp`, `iss` | Standardized by JWT spec |
| **Public claims**     | `email`, `role`, `userId`  | Custom but shareable     |
| **Private claims**    | `cart_id`, `preferences`   | Only used by your app    |
