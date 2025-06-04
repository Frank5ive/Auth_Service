Okay, here's sample JSON data for testing the authentication routes you've provided, based on the `Auth.docx` file.

Remember to replace placeholder values like `your-email@example.com` and `your-strong-password` with actual data you want to use for testing.

```json
{
  "register": {
    "description": "Sample data for user registration",
    "url": "/api/auth/register",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": {
      "email": "testuser@example.com",
      "password": "StrongPassword123!"
    }
  },
  "verifyOTP": {
    "description": "Sample data for OTP verification (after registration)",
    "url": "/api/auth/verify-otp",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": {
      "email": "testuser@example.com",
      "otp": "123456"
    }
  },
  "login": {
    "description": "Sample data for user login",
    "url": "/api/auth/login",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": {
      "email": "testuser@example.com",
      "password": "StrongPassword123!"
    }
  },
  "logout": {
    "description": "Sample data for user logout (requires 'refreshToken' cookie)",
    "url": "/api/auth/logout",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "cookies": {
      "refreshToken": "your_refresh_token_here"
    },
    "body": {}
  },
  "renewToken": {
    "description": "Sample data for renewing access token (requires 'refreshToken' cookie)",
    "url": "/api/auth/renew-token",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "cookies": {
      "refreshToken": "your_refresh_token_here"
    },
    "body": {}
  }
}
```

**Explanation and How to Use:**

- **`register`**:

  - **Purpose:** To create a new user account.
  - **`email`**: The email address for the new user. Make sure it's unique, as the system checks for existing users[cite: 4].
  - **`password`**: The user's desired password. This will be hashed before storage[cite: 5].
  - **Expected Response:** A message indicating successful registration and that an OTP has been sent to the email[cite: 7].

- **`verifyOTP`**:

  - **Purpose:** To activate a newly registered user's account using the OTP sent to their email.
  - **`email`**: The email of the user whose OTP you want to verify[cite: 8].
  - **`otp`**: The 6-digit OTP you receive via email. **This is crucial: you'll need to manually get this from the email sent during registration.** The server expects this OTP to match the one stored in Redis[cite: 11, 12].
  - **Expected Response:** A message confirming OTP verification and account activation[cite: 14].

- **`login`**:

  - **Purpose:** To authenticate an existing, verified user.
  - **`email`**: The email of the registered and verified user.
  - **`password`**: The correct password for that user.
  - **Expected Response:** A message indicating successful login and `accessToken` and `refreshToken` cookies set in the response[cite: 23].

- **`logout`**:

  - **Purpose:** To invalidate the user's session and clear authentication cookies.
  - **`refreshToken` cookie**: This is essential. When a user logs in, the `refreshToken` is set as an `httpOnly` cookie[cite: 23]. To log out, this cookie must be sent with the request. The server deletes the session associated with this token from the database [cite: 25] and Redis[cite: 27].
  - **Expected Response:** A message confirming successful logout and `accessToken` and `refreshToken` cookies cleared[cite: 28].

- **`renewToken`**:
  - **Purpose:** To obtain a new `accessToken` using an existing `refreshToken`. This is typically used to keep a user logged in without requiring them to re-enter their password frequently.
  - **`refreshToken` cookie**: Similar to logout, this cookie is crucial. The server verifies this token [cite: 29] and checks if the session is still valid[cite: 30]. If valid, a new `accessToken` is generated and set as a cookie[cite: 33].
  - **Expected Response:** A message confirming access token renewal and a new `accessToken` cookie set[cite: 34].

**Important Notes for Testing:**

1.  **Order of Operations:** You generally need to `register` -> `verifyOTP` -> `login` to fully test the flow.
2.  **OTP Retrieval:** For `verifyOTP`, you _must_ have access to the email sent by your `sendOTPEmail` service [cite: 50, 51] to get the actual OTP.
3.  **Cookies:** For `logout` and `renewToken`, you'll need to extract the `refreshToken` cookie from the `login` response and include it in subsequent requests for these endpoints. Tools like Postman, Insomnia, or browser developer tools can help manage cookies automatically.
4.  **Error Handling:** The provided code includes error handling for scenarios like existing email[cite: 4], invalid OTP[cite: 12], invalid credentials[cite: 18], unverified accounts[cite: 19], and brute-force protection[cite: 17]. You can test these by providing incorrect data.
5.  **Rate Limiting:** There's a global rate limiter middleware [cite: 35] (100 requests per 900 seconds per IP). Be mindful of this during rapid testing.
6.  **Environment Variables:** Ensure your `.env` file is properly configured with `REDIS_HOST`, `REDIS_PORT`, `REDIS_USERNAME`, `REDIS_PASSWORD`, `GMAIL_USER`, `GMAIL_APP_PASSWORD`, `ACCESS_TOKEN_SECRET`, `REFRESH_TOKEN_SECRET`, `COOKIE_SECRET`, and `DATABASE_URL` as specified in the `server.js` and `prisma/schema.prisma` files[cite: 42, 43, 52, 54, 56].
