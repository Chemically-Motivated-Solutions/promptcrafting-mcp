// tests/integration/enforcement-gates-s3-s8.test.ts
//
// Note:
// The S3–S8 enforcement behaviors (instruction_override, role_impersonation,
// persistent_override, invisible Unicode stripping, and high-entropy payload
// warnings) are covered in detail by the unit tests in:
//
//   tests/unit/input-sanitizer.test.ts
//
// This file is intentionally left without additional tests to avoid
// duplicating unit-level coverage at the same abstraction layer. If true
// end-to-end proofs of the enforcement interceptor are desired, they should
// be added here by driving the real execution path (e.g., via the
// higher-level prompt execution APIs) rather than calling `sanitizeInput`
// directly.
