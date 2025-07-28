### **Project Setup (Quick Start)**

First, create a basic Spring Boot project (Maven or Gradle) with these dependencies:

  * `Spring Web`
  * `Spring Security`
  * `Lombok` (optional, for less boilerplate)

<!-- end list -->

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    </dependencies>
```

-----

## 🧩 Core Concept 1: Authentication vs. Authorization

**💡 Description:**

  * **Authentication (Who are you?):** This is the process of **verifying the identity** of a user. When you log in with a username and password, the system is authenticating you. It confirms that you are who you claim to be.
      * **Analogy:** Showing your ID card to a bouncer at a club entrance.
  * **Authorization (What can you do?):** This is the process of **determining what an authenticated user is allowed to do** or access. Once the system knows who you are, it checks if you have the necessary permissions for a specific action or resource.
      * **Analogy:** The bouncer (who now knows you are over 18) checks your wristband color to see if you can enter the VIP area.

**When to Use Each?**

  * **Authentication:** Always needed for any system that requires users to log in or identify themselves before interacting.
      * **Example:** Sending a username and password to a `/login` endpoint.
  * **Authorization:** Needed for any resource or action that should only be accessible by certain users or roles.
      * **Example:** Only users with `ADMIN` privileges can access the `/admin/dashboard` endpoint or delete a user account. Regular users can only view their own profile.

**Real-World Workflow Example (Login vs. Accessing `/admin`):**

1.  **User tries to Log In (Authentication):**

      * User sends `username: "admin"` and `password: "password"` to `/login`.
      * Spring Security's authentication mechanisms intercept this.
      * It checks if these credentials are valid against its configured user store (e.g., an in-memory user, or a user in a database).
      * **If valid:** User is authenticated. Spring creates an `Authentication` object representing this user and stores it.
      * **If invalid:** Authentication fails. User gets an error (e.g., 401 Unauthorized).

    <!-- end list -->

    ```mermaid
    graph TD
        A[User] -- Credentials (username, password) --> B[Login Endpoint /api/login]
        B -- Intercepted by --> C{Spring Security Filter Chain}
        C -- Delegates to --> D[Authentication Manager]
        D -- Verifies against --> E[UserDetailsService (User Store)]
        E -- Is User Valid? --> D
        D -- Yes --> F[Authentication Object Created]
        F --> G[SecurityContextHolder (Stores Auth Object)]
        G --> H[Response: 200 OK + Session/Token]
        D -- No --> I[Response: 401 Unauthorized]
    ```

2.  **Authenticated User Tries to Access `/admin` (Authorization):**

      * The now authenticated user sends a request to `/api/admin/dashboard`.
      * Spring Security's authorization mechanisms intercept this.
      * It retrieves the user's `Authentication` object from `SecurityContextHolder`.
      * It checks the `Authentication` object's authorities (permissions/roles) to see if the user has the `ROLE_ADMIN`.
      * **If authorized:** Request proceeds to the `/admin/dashboard` controller.
      * **If not authorized:** Request is rejected (e.g., 403 Forbidden).

    <!-- end list -->

    ```mermaid
    graph TD
        A[Authenticated User] -- Request to /api/admin/dashboard --> B{Spring Security Filter Chain}
        B -- Retrieves Auth Object from --> C[SecurityContextHolder]
        B -- Delegates to --> D[Access Decision Manager]
        D -- Checks User's Authorities against --> E[Configured Rules (@PreAuthorize, .hasRole())]
        E -- Is User Allowed? --> D
        D -- Yes --> F[Request proceeds to Controller]
        D -- No --> G[Response: 403 Forbidden]
    ```

**Minimal Code Example:**

Here's how you'd set up basic security in Spring Boot, demonstrating both:

```java
// src/main/java/com/example/securitydemo/config/SecurityConfig.java
package com.example.securitydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity; // Enable method-level security
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity // Enables Spring Security's web security features
@EnableMethodSecurity(prePostEnabled = true) // Enables @PreAuthorize/@PostAuthorize annotations
public class SecurityConfig {

    // 1. Password Encoder (Essential for security)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. In-Memory User Details Service (for basic authentication)
    // In a real app, this would be backed by a database.
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("password")) // Always encode passwords!
                .roles("USER") // Assigns ROLE_USER
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("adminpass"))
                .roles("ADMIN", "USER") // Assigns ROLE_ADMIN and ROLE_USER
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    // 3. Security Filter Chain (defines authorization rules for URLs)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disable CSRF for Postman/API testing (enable in production for web apps)
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/public/**").permitAll() // PUBLIC: No authentication needed
                .requestMatchers("/api/admin/**").hasRole("ADMIN") // AUTHORIZATION: Only users with ROLE_ADMIN
                .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN") // AUTHORIZATION: Any user or admin
                .anyRequest().authenticated() // AUTHENTICATION: All other requests need to be authenticated
            )
            .httpBasic(withDefaults()) // Use HTTP Basic Authentication (good for Postman testing)
            // .formLogin(withDefaults()); // Or form-based login for web apps
            ;
        return http.build();
    }
}
```

```java
// src/main/java/com/example/securitydemo/controller/PublicController.java
package com.example.securitydemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class PublicController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello from the Public API! (No authentication needed)";
    }

    @GetMapping("/user/dashboard")
    // AUTHORIZATION via annotation: Only users with ROLE_USER or ROLE_ADMIN can access
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userDashboard() {
        return "Welcome to the User Dashboard! You are authenticated.";
    }

    @GetMapping("/admin/settings")
    // AUTHORIZATION via annotation: Only users with ROLE_ADMIN can access
    @PreAuthorize("hasRole('ADMIN')")
    public String adminSettings() {
        return "Welcome to Admin Settings! Only admins can see this.";
    }
}
```

**Real-time Use Cases (with Postman):**

1.  **Access `/api/public/hello`:**

      * **Method:** GET
      * **URL:** `http://localhost:8080/api/public/hello`
      * **Result:** 200 OK. No authentication required.

2.  **Access `/api/user/dashboard` (Authentication & Authorization):**

      * **Method:** GET
      * **URL:** `http://localhost:8080/api/user/dashboard`
      * **Authorization (Basic Auth):**
          * **Username:** `user`
          * **Password:** `password`
      * **Result:** 200 OK, returns "Welcome to the User Dashboard\! You are authenticated."
      * **Try with `admin` user:** It will also work because `admin` has `ROLE_USER` too.
      * **Try without auth or wrong auth:** 401 Unauthorized.

3.  **Access `/api/admin/settings` (Authentication & Authorization):**

      * **Method:** GET
      * **URL:** `http://localhost:8080/api/admin/settings`
      * **Authorization (Basic Auth):**
          * **Username:** `admin`
          * **Password:** `adminpass`
      * **Result:** 200 OK, returns "Welcome to Admin Settings\! Only admins can see this."
      * **Try with `user` user:**
          * **Username:** `user`
          * **Password:** `password`
          * **Result:** 403 Forbidden (Authenticated, but not authorized for this resource).

-----

## 🧩 Core Concept 2: Principals & Authorities

**💡 Description:**

Once a user is successfully authenticated, Spring Security bundles all the information about that user into an `Authentication` object. Inside this object, you primarily find:

  * **Principal (Who is it?):** Represents the *identity* of the authenticated user. It's often the `UserDetails` object (which contains the username, password, enabled status, and importantly, authorities), or sometimes just a username string. Think of it as the logged-in user's profile.
  * **Authorities (What can they do?):** These are the specific permissions or roles granted to the Principal. They are represented by `GrantedAuthority` objects. Spring Security uses these to make authorization decisions.

**How to Check Both in Code:**

You can access the `Authentication` object from anywhere in your application after a user has logged in, typically from a controller or service.

**Minimal Code Example:**

```java
// src/main/java/com/example/securitydemo/controller/SecureController.java
package com.example.securitydemo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal; // java.security.Principal is a generic interface

@RestController
@RequestMapping("/api/secure")
public class SecureController {

    // Method 1: Injecting Authentication object
    @GetMapping("/my-info-auth")
    public String getMyInfoWithAuth(Authentication authentication) {
        // Principal: Get the username
        String username = authentication.getName(); // This gives the username

        // Authorities: Get the roles/privileges
        StringBuilder authorities = new StringBuilder();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            authorities.append(authority.getAuthority()).append(" ");
        }

        return String.format("Hello, %s! Your authorities are: %s (accessed via Authentication object)", username, authorities.toString().trim());
    }

    // Method 2: Injecting Principal directly
    @GetMapping("/my-info-principal")
    public String getMyInfoWithPrincipal(Principal principal) {
        // For Spring Security, principal.getName() usually returns the username
        return String.format("Hello, %s! (accessed via java.security.Principal)", principal.getName());
    }

    // Method 3: Injecting UserDetails directly (most common for full user details)
    @GetMapping("/my-info-userdetails")
    public String getMyInfoWithUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        // UserDetails object gives you full details including password (encoded), username, authorities, etc.
        // DO NOT expose password in real APIs.
        StringBuilder authorities = new StringBuilder();
        for (GrantedAuthority authority : userDetails.getAuthorities()) {
            authorities.append(authority.getAuthority()).append(" ");
        }
        return String.format("Hello, %s! Your authorities are: %s (accessed via @AuthenticationPrincipal UserDetails)",
                             userDetails.getUsername(), authorities.toString().trim());
    }
}
```

**How it fits into the Login-Request-Response Cycle:**

1.  **Login:** When `user` logs in, Spring Security successfully authenticates them.
2.  **`Authentication` Object Creation:** Spring Security internally creates an `Authentication` object (often a `UsernamePasswordAuthenticationToken` or similar) that contains:
      * The `Principal` (e.g., a `UserDetails` object for `user`).
      * A collection of `GrantedAuthority` objects (e.g., `ROLE_USER`).
3.  **Storage in `SecurityContextHolder`:** This `Authentication` object is then stored in the `SecurityContextHolder`, making it available throughout the current request thread.
4.  **Access in Controller/Service:** When the user makes subsequent requests (e.g., to `/api/secure/my-info-userdetails`), Spring Security knows who they are, and you can simply inject the `Authentication`, `Principal`, or `UserDetails` object into your method parameters. This information is automatically populated by Spring because it's available in the `SecurityContextHolder`.

-----

## 🧩 Core Concept 3: UsernamePasswordAuthenticationToken

**💡 Description:**

`UsernamePasswordAuthenticationToken` is a concrete implementation of Spring Security's core `Authentication` interface. It's specifically designed to hold **username and password credentials** during the authentication process.

  * **Before Authentication:** When a user submits their username/password, a `UsernamePasswordAuthenticationToken` is created (unauthenticated) to *represent* these credentials. This token is then passed to the `AuthenticationManager`.
  * **After Authentication:** If authentication is successful, the `AuthenticationManager` returns an *authenticated* `UsernamePasswordAuthenticationToken` (or another `Authentication` implementation) which contains the fully populated `Principal` (e.g., `UserDetails`) and its `Authorities`, but the password field is usually cleared for security.

**Why & Where to Use it in Custom Auth Flows?**

You typically don't explicitly create this token yourself for standard Spring Boot form/basic authentication, as Spring Security handles it internally. However, it's crucial in **custom authentication scenarios** where you:

1.  **Authenticate against an external system:** (e.g., LDAP, OAuth2 provider like Google, a legacy database). After you've verified the user externally, you need to tell Spring Security that the user is now authenticated.
2.  **Implement a custom authentication filter:** If you're building a filter that intercepts requests (e.g., for API key authentication, custom JWT validation) and, upon successful validation, you want to set the authenticated user into Spring Security's context.

**Real-World Workflow Example (Simulated Custom Login Flow):**

Imagine a scenario where your users first log in via an OAuth2 provider (like Google or Facebook), and after successful login there, your backend receives a callback. Your backend then needs to tell Spring Security that this user is now logged in.

**Code Example (Simulated Custom Login/API Authentication):**

Let's imagine a scenario where you have a simple API key. If the API key is valid, you want to manually authenticate the user.

```java
// src/main/java/com/example/securitydemo/service/ExternalAuthService.java
package com.example.securitydemo.service;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class ExternalAuthService {

    /**
     * Simulates external authentication (e.g., after validating an API key or OAuth token).
     * If external validation is successful, this method can manually set the authentication.
     */
    public boolean authenticateExternalUser(String providedApiKey) {
        // --- STEP 1: Simulate external validation ---
        // In a real app, this would be a call to an external service or database lookup.
        if (!"VALID_API_KEY_123".equals(providedApiKey)) {
            return false; // Authentication failed
        }

        // --- STEP 2: If external validation succeeds, create UserDetails for Spring Security ---
        // This UserDetails object represents the authenticated user's identity and authorities.
        UserDetails userDetails = User.builder()
                .username("apiUser")
                .password("") // Password is not relevant here as authentication happened externally
                .authorities(Collections.singletonList(new SimpleGrantedAuthority("ROLE_API_USER")))
                .build();

        // --- STEP 3: Create an authenticated UsernamePasswordAuthenticationToken ---
        // The first argument is the Principal (UserDetails), second is credentials (null if already authenticated),
        // third is authorities. Mark it as authenticated.
        UsernamePasswordAuthenticationToken authenticatedToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        // --- STEP 4: Manually set the Authentication object in the SecurityContextHolder ---
        // This tells Spring Security that the current request thread is now authenticated as this user.
        SecurityContextHolder.getContext().setAuthentication(authenticatedToken);

        return true; // Authentication successful
    }
}
```

```java
// src/main/java/com/example/securitydemo/controller/ApiKeyController.java
package com.example.securitydemo.controller;

import com.example.securitydemo.service.ExternalAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/apikey")
public class ApiKeyController {

    @Autowired
    private ExternalAuthService externalAuthService;

    @GetMapping("/secure-resource")
    @PreAuthorize("hasRole('API_USER')") // Only users authenticated via API key with ROLE_API_USER
    public ResponseEntity<String> accessSecureResource(@RequestHeader("X-API-KEY") String apiKey) {
        // Here, you could technically re-authenticate or just rely on a filter that did it.
        // For demonstration, let's assume a filter or an interceptor calls authenticateExternalUser.
        // If this method is reached, it implies an authentication mechanism already worked.
        // For this specific example, let's make it more direct for teaching purposes.

        // In a real scenario, an AuthenticationFilter would do this before the controller
        // For learning purposes, we'll call it here (not ideal for production but shows token use)
        if (!externalAuthService.authenticateExternalUser(apiKey)) {
            return new ResponseEntity<>("Invalid API Key", HttpStatus.UNAUTHORIZED);
        }

        return new ResponseEntity<>("Accessed secure resource with API Key!", HttpStatus.OK);
    }
}
```

**Workflow for API Key with `UsernamePasswordAuthenticationToken` (Conceptual):**

1.  **Request with API Key:** User sends request to `/api/apikey/secure-resource` with `X-API-KEY: VALID_API_KEY_123`.
2.  **Filter/Interceptor:** A custom Spring Security Filter (which you'd write) intercepts this.
3.  **External Validation:** The filter extracts the API key and sends it to `ExternalAuthService.authenticateExternalUser()`.
4.  **`UsernamePasswordAuthenticationToken` Creation:** If `ExternalAuthService` validates the key, it creates an `authenticatedToken` (a `UsernamePasswordAuthenticationToken`) and sets it into `SecurityContextHolder`.
5.  **Proceed to Controller:** The request proceeds.
6.  **Authorization:** The `@PreAuthorize("hasRole('API_USER')")` on the controller method checks the authorities now present in `SecurityContextHolder`.
7.  **Response:** If authorized, method executes; otherwise, 403 Forbidden.

**Diagram (API Key Authentication - Textual Description):**

```
User (with API Key) ---Request---> Custom Authentication Filter
                                       |
                                       V
                                API Key Validation (e.g., ExternalAuthService)
                                       |
                                       V
                       IF Valid: Create new UsernamePasswordAuthenticationToken (authenticated)
                                       |
                                       V
                     Set Token into SecurityContextHolder.getContext().setAuthentication()
                                       |
                                       V
         (Filter Chain continues) ---Proceed to Controller---
                                       |
                                       V
          @PreAuthorize (checks SecurityContextHolder for roles)
                                       |
                                       V
                           Access Granted/Denied
```

-----

## 🧩 Core Concept 4: SecurityContext & SecurityContextHolder

**💡 Description:**

This is where Spring Security keeps track of **who the current user is** in any given request.

  * **`SecurityContext`:** This is an interface representing the "security context" for the current principal. It holds the `Authentication` object, which in turn contains the `Principal` (user details) and their `GrantedAuthority` objects (roles/permissions).
  * **`SecurityContextHolder`:** This is a static helper class provided by Spring Security. It uses a `ThreadLocal` strategy by default. This means that once a user is authenticated in a web request, their `SecurityContext` (and thus their `Authentication` object) is automatically available to *any* code running on that same request thread, without you having to pass it around explicitly.

**Where does Spring store user login info after authentication?**
It stores it in the `SecurityContext`, which is managed by the `SecurityContextHolder`. This `ThreadLocal` mechanism ensures isolation between concurrent requests.

**How do I access it from any service class?**

You can access it directly via `SecurityContextHolder.getContext().getAuthentication()`.

**Real-World Workflow Example & Code:**

Imagine you have a `ProductService` that needs to log which user performed a specific action, or apply a business rule based on the user's role.

```java
// src/main/java/com/example/securitydemo/service/ProductService.java
package com.example.securitydemo.service;

import org.springframework.security.access.AccessDeniedException; // For custom access denied
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class ProductService {

    public String createProduct(String productName) {
        // Accessing SecurityContextHolder from a Service class
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            // Check if user has specific authority from service layer logic
            boolean isAdmin = authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            if (!isAdmin) {
                // If not an admin, we might throw a custom access denied exception
                // or return a specific message, demonstrating authorization logic
                // within a service. For strict authorization, @PreAuthorize on controller is better.
                throw new AccessDeniedException("Only admins can create products.");
            }

            // Real business logic for creating product...
            System.out.println(username + " (Admin) is creating product: " + productName);
            return "Product '" + productName + "' created by " + username;
        } else {
            // This path should ideally not be reached if security filters are set up correctly,
            // as unauthenticated users shouldn't reach this service method.
            throw new IllegalStateException("User not authenticated to create product.");
        }
    }

    // You can also use @PreAuthorize directly on service methods
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('USER')")
    public String viewProductDetails(Long productId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName(); // Get username of current user
        return "Viewing details for product " + productId + " as user: " + username;
    }
}
```

```java
// src/main/java/com/example/securitydemo/controller/ProductController.java
package com.example.securitydemo.controller;

import com.example.securitydemo.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    @Autowired
    private ProductService productService;

    @PostMapping("/create")
    public ResponseEntity<String> createProduct(@RequestParam String name) {
        // @PreAuthorize here delegates the primary authorization check
        // You can still access SecurityContextHolder within the service for audit/context
        return ResponseEntity.ok(productService.createProduct(name));
    }

    @GetMapping("/{id}")
    public ResponseEntity<String> getProduct(@PathVariable Long id) {
        return ResponseEntity.ok(productService.viewProductDetails(id));
    }
}
```

**Diagram (SecurityContextHolder Flow):**

```
                                               +-------------------------+
                                               |    SecurityContextHolder|
                                               |  (ThreadLocal Storage)  |
                                               |       +---------------+ |
                                               |       | SecurityContext |
                                               |       |  +------------+ |
Request Thread A (User 'admin') -------------->|       |  | Authentication |
                                               |       |  |  (Principal: admin) |
                                               |       |  |  (Authorities: ROLE_ADMIN, ROLE_USER) |
                                               |       |  +------------+ |
                                               |       +---------------+ |
Request Thread B (User 'user') --------------->|         (Separate Context for each thread)
                                               |       +---------------+ |
                                               |       | SecurityContext |
                                               |       |  +------------+ |
                                               |       |  | Authentication |
                                               |       |  |  (Principal: user) |
                                               |       |  |  (Authorities: ROLE_USER) |
                                               |       |  +------------+ |
                                               |       +---------------+ |
                                               +-------------------------+
                                                           |
                                                           V
            (Anywhere in code on that thread)               Controller / Service / Repository
            `SecurityContextHolder.getContext().getAuthentication()` is accessible
```

-----

## 🧩 Core Concept 5: Role vs. Authority

**💡 Description:**

While often used interchangeably by beginners, Spring Security makes a distinction between roles and more granular authorities (or privileges).

  * **Role:**
      * **Purpose:** Represents a high-level grouping of permissions or a general function within the application. It's a broad category.
      * **Convention:** Often prefixed with `ROLE_` (e.g., `ROLE_ADMIN`, `ROLE_USER`, `ROLE_MANAGER`). Spring Security's `hasRole()` method automatically adds this prefix for you.
      * **Example:** An `ADMIN` role might imply permissions to "create users", "delete users", "view all reports". A `USER` role might imply "view own profile", "create post".
  * **Authority (or Privilege):**
      * **Purpose:** Represents a very specific, granular permission to perform an action.
      * **Convention:** No specific prefix, usually descriptive (e.g., `USER_CREATE`, `USER_READ`, `PRODUCT_DELETE`, `REPORT_VIEW`).
      * **Example:** Instead of a `MANAGER` role, you might give a user `PRODUCT_APPROVE` and `ORDER_VIEW` authorities directly.

**When to Use Which?**

  * **Use `ROLE_` (Roles) for:**
      * **Broad access control:** When you want to define general user types in your application.
      * **Simple authorization rules:** `hasRole('ADMIN')` is concise and easy to read.
      * **UI element visibility:** Often, entire sections of a UI are shown/hidden based on a user's role.
  * **Use `hasAuthority()` (Authorities/Privileges) for:**
      * **Fine-grained authorization:** When you need very specific control over individual actions or resources.
      * **Complex permission matrices:** A user might have specific authorities from different roles.
      * **Beyond simple roles:** A user might not fit a standard role but needs specific permissions (e.g., a "power user" who can "edit product price" but isn't a full "admin").

**How to Structure These in Real Apps:**

1.  **Define Authorities (Privileges):** Start by listing all the granular actions a user might perform (e.g., `USER_READ`, `USER_WRITE`, `PRODUCT_VIEW`, `PRODUCT_EDIT`, `ORDER_CANCEL`, `REPORT_GENERATE`). These often map closely to CRUD operations on entities.
2.  **Define Roles:** Group these authorities into meaningful roles.
      * **`ROLE_ADMIN`:** `USER_READ`, `USER_WRITE`, `PRODUCT_VIEW`, `PRODUCT_EDIT`, `ORDER_CANCEL`, `REPORT_GENERATE` (all of them).
      * **`ROLE_MANAGER`:** `PRODUCT_VIEW`, `PRODUCT_EDIT`, `ORDER_VIEW`, `REPORT_GENERATE`.
      * **`ROLE_USER`:** `USER_READ`, `PRODUCT_VIEW`.
3.  **Assign Roles to Users:** In your database, users are assigned one or more roles.
4.  **Derive Authorities from Roles:** When a user logs in, your `UserDetailsService` (or custom implementation) retrieves the user's roles from the database. Then, for each role, it looks up the associated granular authorities and returns all of them as `GrantedAuthority` objects.

**Minimal Code Example:**

**1. `UserDetailsService` (Returning both roles and authorities):**

```java
// src/main/java/com/example/securitydemo/service/CustomUserDetailsService.java
package com.example.securitydemo.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    // Inject PasswordEncoder here
    public CustomUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // A dummy user store for demonstration (in real app, this is database lookup)
    private static final List<UserDetails> users = new ArrayList<>();
    static {
        // Admin: Has ROLE_ADMIN and specific granular authorities
        users.add(User.builder()
                .username("admin")
                .password("$2a$10$w3vQx.5G.0Z4K.4L.6T4D.o2J.6V.9D.9J.7C.9S.0W.1L.8P.2M.3K.4N.5O.6Q.7R.8S.9T.0U.1V.2W.3X.4Y.5Z.") // encrypted 'adminpass'
                .authorities(getAuthorities("ADMIN", "USER_CREATE", "USER_DELETE", "PRODUCT_EDIT", "REPORT_GENERATE"))
                .build());

        // User: Has ROLE_USER and specific granular authority
        users.add(User.builder()
                .username("user")
                .password("$2a$10$w3vQx.5G.0Z4K.4L.6T4D.o2J.6V.9D.9J.7C.9S.0W.1L.8P.2M.3K.4N.5O.6Q.7R.8S.9T.0U.1V.2W.3X.4Y.5Z.") // encrypted 'password'
                .authorities(getAuthorities("USER", "PRODUCT_VIEW"))
                .build());
    }

    // Helper to convert roles/authorities strings to GrantedAuthority objects
    private static Collection<? extends GrantedAuthority> getAuthorities(String... authorities) {
        return Arrays.stream(authorities)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }
}
```

*(Note: I replaced `InMemoryUserDetailsManager` with a `CustomUserDetailsService` to show how to manually assign specific `SimpleGrantedAuthority` objects which can include both `ROLE_` prefixes and granular authorities. The encoded passwords are dummy examples for `adminpass` and `password` respectively).*

**2. Securing Endpoints with Both `hasRole` and `hasAuthority`:**

```java
// src/main/java/com/example/securitydemo/controller/PermissionsController.java
package com.example.securitydemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/permissions")
public class PermissionsController {

    // Authorization based on high-level Role
    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('ADMIN')") // Spring automatically prefixes with ROLE_
    public String adminOnlyEndpoint() {
        return "This is accessible only by users with ROLE_ADMIN.";
    }

    // Authorization based on granular Authority/Privilege
    @PostMapping("/create-user")
    @PreAuthorize("hasAuthority('USER_CREATE')") // Checks for the specific authority string
    public String createUserEndpoint(@RequestParam String username) {
        return "User " + username + " created. (Requires USER_CREATE authority)";
    }

    @DeleteMapping("/delete-user")
    @PreAuthorize("hasAuthority('USER_DELETE')") // Checks for the specific authority string
    public String deleteUserEndpoint(@PathVariable Long userId) {
        return "User " + userId + " deleted. (Requires USER_DELETE authority)";
    }

    @PutMapping("/edit-product/{id}")
    @PreAuthorize("hasAuthority('PRODUCT_EDIT')") // Checks for PRODUCT_EDIT authority
    public String editProductEndpoint(@PathVariable Long id) {
        return "Product " + id + " edited. (Requires PRODUCT_EDIT authority)";
    }

    @GetMapping("/view-product-status")
    @PreAuthorize("hasAuthority('PRODUCT_VIEW') or hasAuthority('REPORT_GENERATE')") // Multiple granular authorities
    public String viewProductStatus() {
        return "Viewing product status. (Requires PRODUCT_VIEW or REPORT_GENERATE authority)";
    }
}
```

**Real-time Use Cases (with Postman):**

  * **Login as `admin` (password: `adminpass`)**:

      * **Try `/api/permissions/admin-only`:** Success (200 OK) because `admin` has `ROLE_ADMIN`.
      * **Try `/api/permissions/create-user` (POST):** Success (200 OK) because `admin` has `USER_CREATE` authority.
      * **Try `/api/permissions/edit-product/123` (PUT):** Success (200 OK) because `admin` has `PRODUCT_EDIT` authority.

  * **Login as `user` (password: `password`)**:

      * **Try `/api/permissions/admin-only`:** 403 Forbidden (Authenticated, but doesn't have `ROLE_ADMIN`).
      * **Try `/api/permissions/create-user` (POST):** 403 Forbidden (Authenticated, but doesn't have `USER_CREATE` authority).
      * **Try `/api/permissions/view-product-status`:** Success (200 OK) because `user` has `PRODUCT_VIEW` authority.
