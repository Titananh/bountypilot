import type { ProviderChatMessage } from "../../providers/provider-chat-client.js";

export const TUI_DEMO_TITLE = "Scoped recon to report-ready bounty workflow";
export const TUI_DEMO_USER = "Find exposed endpoints for the scoped target and prepare safe bounty evidence";

export function tuiDemoAssistantLines(modelLabel = "Claude Opus 4.5"): string[] {
  return [
    "I'll map the in-scope surface first, then separate weak recon signals from reportable findings.",
    "",
    '* Recon "host" observations (14)',
    '* Recon "url" observations (38)',
    '* Tool plan "subfinder -> httpx -> katana" queued for dry-run review',
    "",
    "-> Read .bounty/programs/demo.yml",
    "-> Queue bugbounty hunt recon demo.example.com --profile web --dry-run",
    "",
    "I found several candidate endpoints. The next step is evidence capture before creating a finding.",
    "",
    "~ Waiting for approval...",
    "",
    `◉ Build · ${modelLabel}`,
  ];
}

export function tuiDemoMessages(systemPrompt: string, modelLabel?: string): ProviderChatMessage[] {
  return [
    { role: "system", content: systemPrompt },
    { role: "user", content: TUI_DEMO_USER },
    { role: "assistant", content: tuiDemoAssistantLines(modelLabel).join("\n") },
  ];
}
