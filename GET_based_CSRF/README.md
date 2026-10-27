# CSRF Variant 1 — GET-based forged action

**Course:** Web Server Security (IT-30001), Autumn 2026  
**Selected topic:** Cross-Site Request Forgery, Variant 1 (GET-based forged action)  
**Owner:** [Your name] · **Roll number:** [Your roll number]

> This is a deliberately vulnerable, local-only teaching demo. It uses an in-memory simulated account and is bound to `127.0.0.1`. Do not deploy it or test it against any other system.

## Run

Requires Node.js 18 or newer. There are no third-party dependencies.

```sh
npm start
```

Open <http://127.0.0.1:3000>. Each browser session starts with a simulated `$1000` balance. Session state is in memory and resets when the server restarts.

## Demonstration

1. In the main page, choose **Vulnerable mode**. Open **local attacker page** in a second tab.
2. Click **Trigger forged GET transfer ($100)**. Return to the account page and reload: the balance has fallen by `$100`. The attacker request is a GET to `/transfer?amount=100` and carries the victim browser's session cookie.
3. Choose **Secure mode**, then repeat the same attacker action. The GET is rejected with HTTP 405 and the balance remains unchanged. This mitigation moves state changes off GET; the transfer is available only by POST and requires a per-session CSRF token.

For a clean recording, restart the server to reset balances, then show vulnerable mode first and secure mode second. The attacker page also includes an image-triggered GET to illustrate a forged cross-site subresource request.

## Vulnerability and root cause

In `server.js`, the `GET /transfer` handler changes the account balance using a query parameter. In vulnerable mode it neither checks user intent nor requires a secret unavailable to another site. Browsers automatically attach eligible cookies to requests, so a logged-in victim can be induced to trigger the action.

## Mitigation implemented

The selected primary mitigation is **avoiding state-changing GET requests**: secure mode rejects `GET /transfer` with 405; transfers use POST instead. The POST handler checks a cryptographically random session-bound synchronizer token, preventing an external site from creating a valid request. The mode-switch form is also token-protected. The cookie is `HttpOnly; SameSite=Lax`; cookie policy is defense-in-depth, not the sole control.

## Other CSRF mitigations (theory)

- **Synchronizer tokens:** Put an unpredictable token in each state-changing form and validate it server-side against the user's session. An attacking origin cannot read the legitimate page to obtain the token (assuming same-origin protections).
- **SameSite cookies:** `Strict` or `Lax` can prevent cookies accompanying many cross-site requests. This reduces exposure but has browser/context caveats and should not replace request validation.
- **Re-authentication:** Ask for a password, MFA, or another fresh confirmation for especially sensitive actions, so a forged background request is insufficient.
- **Avoid state-changing GETs:** GET is expected to be safe and can be triggered by links, images, crawlers, and prefetching. Use a protected non-GET request for mutations.

## Ownership declaration

| Member name | Roll number | Category | Variant implemented |
|---|---|---|---|
| [Your name] | [Your roll number] | CSRF | Variant 1 — GET-based forged action |

Fill in your actual details before submission. The assignment asks the group to map each variant to its individual owner.

## Files

- `server.js` — local demo server, vulnerable path, protected path, and attacker page.
- `VIDEO_SCRIPT.md` — suggested two-to-three-minute individual narration and demo sequence.
