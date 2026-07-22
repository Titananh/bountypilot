import { z } from "zod";

export const PROGRAM_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function isValidProgramName(value: string): boolean {
  return PROGRAM_NAME_PATTERN.test(value);
}

const RateLimitSchema = z
  .string()
  .regex(/^\d+(\.\d+)?rps$/, "Rate limit must look like 1rps or 0.5rps")
  .default("1rps");

const LabAuthorizationFileSchema = z
  .string()
  .trim()
  .min(1)
  .refine(
    (value) =>
      !/[\0\r\n;&|`$<>]/.test(value) &&
      !/^(?:[A-Za-z]:)?[\\/]/.test(value) &&
      value !== ".." &&
      !value.replace(/\\/g, "/").split("/").includes(".."),
    "Lab authorization file must be a safe relative path inside the program workspace",
  );

const ScopeRuleSchema = z
  .string()
  .trim()
  .min(1)
  .refine(
    (value) => {
      if (!hasExplicitScheme(value)) {
        return !/[/?#@]/.test(value);
      }
      try {
        const parsed = new URL(value);
        return (
          (parsed.protocol === "http:" || parsed.protocol === "https:") &&
          parsed.hostname.length > 0 &&
          parsed.username === "" &&
          parsed.password === "" &&
          parsed.search === "" &&
          parsed.hash === "" &&
          !hasPercentEncodedPathOctet(parsed.pathname)
        );
      } catch {
        return false;
      }
    },
    "Scope rules must be http(s), contain no credentials/query/fragment, and use a host-only or path-prefix form",
  );

export const ProgramSchema = z.object({
  program: z
    .string()
    .trim()
    .min(1)
    .regex(PROGRAM_NAME_PATTERN, "Program name may only contain letters, numbers, dots, underscores, and hyphens"),
  platform: z.string().min(1).default("hackerone"),
  in_scope: z.array(ScopeRuleSchema).min(1),
  out_of_scope: z.array(ScopeRuleSchema).default([]),
  rules: z
    .object({
      automated_scanning: z.enum(["none", "limited", "allowed"]).default("limited"),
      destructive_testing: z.boolean().default(false),
      rate_limit: RateLimitSchema,
      browser_crawling: z.boolean().default(true),
      deep_safe_mode: z.boolean().default(true),
      lab_mode: z.boolean().optional(),
      lab_authorization_file: LabAuthorizationFileSchema.optional(),
      require_human_approval_for_risky_actions: z.boolean().default(true),
    })
    .default({
      automated_scanning: "limited",
      destructive_testing: false,
      rate_limit: "1rps",
      browser_crawling: true,
      deep_safe_mode: true,
      lab_mode: false,
      require_human_approval_for_risky_actions: true,
    }),
  accounts: z
    .object({
      required: z.boolean().default(false),
      use_researcher_owned_test_accounts_only: z.boolean().default(true),
    })
    .default({
      required: false,
      use_researcher_owned_test_accounts_only: true,
    }),
  evidence: z
    .object({
      screenshots: z.boolean().default(true),
      har: z.boolean().default(true),
      console_logs: z.boolean().default(true),
      dom_snapshot: z.boolean().default(true),
      video: z.union([z.boolean(), z.literal("optional")]).default("optional"),
      browser_trace: z.boolean().default(true),
      desktop_screenshots: z.union([z.boolean(), z.literal("optional")]).default("optional"),
      mask_secrets: z.boolean().default(true),
    })
    .default({
      screenshots: true,
      har: true,
      console_logs: true,
      dom_snapshot: true,
      video: "optional",
      browser_trace: true,
      desktop_screenshots: "optional",
      mask_secrets: true,
    }),
  integrations: z.record(z.string(), z.unknown()).default({}),
});

export type ProgramConfig = z.infer<typeof ProgramSchema>;

function hasExplicitScheme(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
}

function hasPercentEncodedPathOctet(pathname: string): boolean {
  // Path-scoped authorization must not depend on how many decode/normalize
  // passes an origin server performs. Reject encoded octets conservatively.
  return /%[0-9a-f]{2}/i.test(pathname);
}
