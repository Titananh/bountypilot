# Reproduction Notes

Target: `https://api.example.com/health`

1. Confirm the target is explicitly in scope.
2. Send a single safe request with `bounty check https://api.example.com/health --safe --mode safe`.
3. Observe that the response does not include a strict `Content-Security-Policy` header.
4. Treat the result as low reportability unless a safe impact chain is demonstrated.

No authentication, real user data, form submission, brute force, or destructive action is used in this sample.
