## 🎯 **Goal of This Program:**

To use **JWT token-based authentication** so that:

* When a user logs in, they get a **secure token**
* That token is sent with every request to access protected APIs
* The server **verifies the token** to check who the user is

---

## 🧠 Real-Time Workflow: Imagine a Project Management App

---

### ✅ Step 1: **User Logs In**

👩 User: *"Hi, I’m logging in with my email & password."*

* You call:

```java
Authentication authentication = authenticationManager.authenticate(
    new UsernamePasswordAuthenticationToken(email, password));
```

* If email and password are valid, you pass `authentication` to:

```java
String token = JwtProvider.generateToken(authentication);
```

---

### ✅ What `generateToken()` Does:

This method builds a token:

```java
claims.put("email", authentication.getName()); // Stores email inside token
```

It returns a token like:

```
eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImpvaG5AZ21haWwuY29tIn0...
```

### 📦 Server sends this token to the frontend:

```json
{
  "token": "Bearer eyJhbGciOiJIUzI1NiJ9..."
}
```

The **frontend stores it in localStorage or sessionStorage**.

---

### ✅ Step 2: **Frontend Sends Token With Every API Request**

When user accesses `/api/projects`, the frontend adds the token in the request header:

```http
GET /api/projects
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

---

### ✅ Step 3: **Backend Reads and Validates Token**

On the backend, your filter (like `JwtTokenValidator`) does this:

```java
String email = JwtProvider.getEmailFromToken(jwt); // Extracts email from JWT
```

➡️ Internally, it does:

```java
jwt = jwt.substring(7); // Removes "Bearer "
Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();
String email = (String) claims.get("email");
```

Now the backend **knows who is making the request** — based on the email inside the token.

---

### ✅ Step 4: **Spring Security Authenticates the User**

* It loads the user by email from DB
* Sets the user info in the Spring Security context
* Lets the request continue to the controller

---

### ✅ Step 5: **Controller Logic Runs**

Now your controller method can do:

```java
@GetMapping("/api/projects")
public ResponseEntity<?> getProjects(Authentication auth) {
   System.out.println(auth.getName()); // Prints the email from JWT
   return projectService.getProjectsByEmail(auth.getName());
}
```

---

## 🔁 Summary of the Workflow

| Step | Action                                                   |
| ---- | -------------------------------------------------------- |
| 1️⃣  | User logs in with email + password                       |
| 2️⃣  | Server validates credentials & returns JWT token         |
| 3️⃣  | Frontend saves token and sends it with every API request |
| 4️⃣  | Backend reads the token, extracts email                  |
| 5️⃣  | Spring Security verifies and allows the request          |
| 6️⃣  | Controller runs logic with the authenticated user's info |

---

## 🔐 Diagram Overview (Text Version)

```
[Frontend]
  ↓ (email + password)
[Backend Login API]
  → Verify → ✅ JWT Generated
  → Return token to frontend

[Frontend]
  → Save token in localStorage
  → Make requests:
     GET /api/projects
     Authorization: Bearer <token>

[Backend]
  → JwtTokenValidator reads token
  → Email is extracted
  → Spring sets user in SecurityContext
  → Controller uses that user
```

---

## 🚀 Real-Life Example

> Think of JWT like a **visitor badge** at a secure building:

* When you log in at reception, you get a badge (JWT).
* You show the badge at every door.
* Security checks your badge and lets you in (or not) — no need to ask your name every time.
