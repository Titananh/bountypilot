import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import React, { useEffect, useMemo, useState } from "react";
import { Box, Text, useApp, useInput, useStdout } from "ink";
import { workspacePaths } from "../../core/workspace.js";
import type { ProviderChatMessage } from "../../providers/provider-chat-client.js";
import { ProviderChatClient } from "../../providers/provider-chat-client.js";
import { PROVIDER_CATALOG, ProviderManager, type ProviderCatalogEntry, type ProviderSummary } from "../../providers/provider-manager.js";
import { BountyPilotError } from "../../utils/errors.js";
import {
  SLASH_COMMANDS,
  TUI_MODES,
  appendPromptHistory,
  appendRecentModel,
  backspaceComposerText,
  boundedComposerCursor,
  classifyAssistantLine,
  cycleModelOption,
  deleteComposerText,
  displayModelLabel,
  filterSlashCommands,
  formatTranscriptTitleMetrics,
  insertComposerText,
  killComposerAfterCursor,
  killComposerWordBeforeCursor,
  maskedInput,
  nextTuiMode,
  parseSlashCommand,
  previousTuiMode,
  safeComposerAppend,
  sortModelOptionsByRecent,
  truncateTuiText,
  windowItemsFromEnd,
  type SlashCommandSpec,
  type TuiAssistantLineKind,
  type TuiModelOption,
  type TuiMode,
  type TuiScreen,
} from "./state.js";
import { TuiSessionStore, type TuiSessionRecord, type TuiSessionSummary } from "./session-store.js";
import { buildContextPrompt, listContextFiles, type ContextFileEntry } from "./context.js";
import { TUI_THEMES, themeById, type TuiTheme, type TuiThemeId } from "./theme.js";
import { loadWorkspaceInsight, type TuiWorkspaceInsight } from "./workspace-intelligence.js";
import { TuiSettingsStore } from "./settings-store.js";
import { loadCustomCommands, renderCustomCommandPrompt, type TuiCustomCommand } from "./custom-commands.js";
import { TUI_DEMO_TITLE, tuiDemoMessages } from "./demo.js";

export interface BountyPilotTuiAppProps {
  cwd: string;
  providerId?: string;
  model?: string;
  systemPrompt: string;
  temperature: number;
  maxTokens: number;
  demoSession?: boolean;
}

type ConnectStage = "provider" | "api-key";
type NoticeKind = "info" | "ok" | "warn" | "error";
type InputKey = Parameters<Parameters<typeof useInput>[0]>[1];

interface Notice {
  kind: NoticeKind;
  text: string;
}

const SAFE_ACTIONS = [
  {
    title: "Doctor",
    command: "bugbounty hunt doctor <target> --profile web",
    note: "Checks scope, provider, and tool readiness without scanning.",
  },
  {
    title: "Recon dry-run",
    command: "bugbounty hunt recon <target> --profile web --dry-run",
    note: "Plans recon observations and queues review-required tools only.",
  },
  {
    title: "XSS playbook dry-run",
    command: "bugbounty hunt playbook xss <target> --dry-run",
    note: "Creates weak signals as observations unless evidence is strong enough.",
  },
  {
    title: "Results board",
    command: "bugbounty results --min-score 60",
    note: "Shows report-ready findings, blockers, and next evidence steps.",
  },
];
const PALETTE_VISIBLE_LIMIT = 8;
const PICKER_VISIBLE_LIMIT = 8;
const CONTENT_MAX_WIDTH = 86;
const HELP_COMMAND_IDS = ["/connect", "/models", "/mode", "/sessions", "/themes", "/new", "/compact", "/init", "/hunt", "/doctor", "/results", "/exit"];

export function BountyPilotTuiApp(props: BountyPilotTuiAppProps): React.ReactNode {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const manager = useMemo(() => new ProviderManager(props.cwd), [props.cwd]);
  const client = useMemo(() => new ProviderChatClient(manager), [manager]);
  const sessions = useMemo(() => new TuiSessionStore(props.cwd), [props.cwd]);
  const settingsStore = useMemo(() => new TuiSettingsStore(props.cwd), [props.cwd]);
  const initialSettings = useMemo(() => settingsStore.read(), [settingsStore]);
  const initialThemeId = useMemo(
    () => themeById(process.env.BOUNTYPILOT_TUI_THEME ?? initialSettings.theme).id,
    [initialSettings.theme],
  );
  const initialProviders = useMemo(() => safeProviderList(manager), [manager]);
  const customCommands = useMemo(() => loadCustomCommands(props.cwd), [props.cwd]);
  const initialProvider = useMemo(
    () => resolveInitialProvider(manager, initialProviders, props.providerId),
    [manager, initialProviders, props.providerId],
  );
  const initialModel = props.model ?? initialProvider?.model;
  const initialModelLabel = props.demoSession && !initialProvider && !initialModel
    ? "Claude Opus 4.5"
    : displayModelLabel(initialProvider?.id, initialModel);
  const initialMessages = useMemo(
    () =>
      props.demoSession
        ? tuiDemoMessages(props.systemPrompt, initialModelLabel)
        : [{ role: "system" as const, content: props.systemPrompt }],
    [initialModelLabel, props.demoSession, props.systemPrompt],
  );
  const initialSession = useMemo(
    () =>
      sessions.create({
        title: props.demoSession ? TUI_DEMO_TITLE : undefined,
        providerId: initialProvider?.id,
        model: initialModel,
        messages: initialMessages,
      }),
    [initialMessages, initialModel, initialProvider?.id, props.demoSession, sessions],
  );

  const [providers, setProviders] = useState<ProviderSummary[]>(initialProviders);
  const [session, setSession] = useState<TuiSessionRecord>(initialSession);
  const [messages, setMessages] = useState<ProviderChatMessage[]>(initialSession.messages);
  const [undoStack, setUndoStack] = useState<ProviderChatMessage[][]>([]);
  const [redoStack, setRedoStack] = useState<ProviderChatMessage[][]>([]);
  const [mode, setMode] = useState<TuiMode>(initialSession.mode);
  const [themeId, setThemeId] = useState<TuiThemeId>(initialThemeId);
  const [showDetails, setShowDetails] = useState(initialSettings.details);
  const [showThinking, setShowThinking] = useState(initialSettings.thinking);
  const [recentModels, setRecentModels] = useState<string[]>(initialSettings.recentModels);
  const [screen, setScreen] = useState<TuiScreen>(props.demoSession || initialProvider ? "chat" : "connect");
  const [previousScreen, setPreviousScreen] = useState<TuiScreen>("chat");
  const [provider, setProvider] = useState<ProviderSummary | undefined>(initialProvider);
  const [model, setModel] = useState<string | undefined>(initialModel);
  const [composer, setComposer] = useState("");
  const [composerCursor, setComposerCursor] = useState(0);
  const [selected, setSelected] = useState(0);
  const [connectStage, setConnectStage] = useState<ConnectStage>("provider");
  const [pendingProvider, setPendingProvider] = useState<ProviderCatalogEntry | undefined>(PROVIDER_CATALOG[0]);
  const [apiKey, setApiKey] = useState("");
  const [providerQuery, setProviderQuery] = useState("");
  const [modelQuery, setModelQuery] = useState("");
  const [sessionQuery, setSessionQuery] = useState("");
  const [transcriptScrollOffset, setTranscriptScrollOffset] = useState(0);
  const [promptHistory, setPromptHistory] = useState<string[]>(() => promptHistoryFromMessages(initialSession.messages));
  const [historyCursor, setHistoryCursor] = useState<number | undefined>(undefined);
  const [historyDraft, setHistoryDraft] = useState("");
  const [contextFiles, setContextFiles] = useState<string[]>(initialSession.contextFiles ?? []);
  const [fileQuery, setFileQuery] = useState("");
  const [leaderArmed, setLeaderArmed] = useState(false);
  const [insight, setInsight] = useState<TuiWorkspaceInsight>(() => loadWorkspaceInsight(props.cwd));
  const [notice, setNotice] = useState<Notice>({ kind: "info", text: "" });
  const [busy, setBusy] = useState(false);
  const [exitArmed, setExitArmed] = useState(false);

  const width = stdout.columns || 100;
  const height = stdout.rows || 30;
  const theme = themeById(themeId);
  const visibleMessages = messages.filter((message) => message.role !== "system");
  const overlayActive = isOverlayScreen(screen);
  const transcriptLimit = Math.max(3, Math.min(overlayActive ? 7 : 18, height - (overlayActive ? 20 : 10)));
  const transcriptWindow = windowItemsFromEnd(visibleMessages, transcriptLimit, transcriptScrollOffset);
  const providerOptions = useMemo(() => filterProviders(PROVIDER_CATALOG, providerQuery), [providerQuery]);
  const configuredModelOptions = useMemo(() => sortModelOptionsByRecent(providerModelOptions(providers), recentModels), [providers, recentModels]);
  const modelOptions = useMemo(() => sortModelOptionsByRecent(providerModelOptions(providers, modelQuery), recentModels), [providers, modelQuery, recentModels]);
  const visibleModelOptions = modelOptions.slice(0, PICKER_VISIBLE_LIMIT);
  const sessionOptions = sessions.list();
  const filteredSessionOptions = filterSessionOptions(sessionOptions, sessionQuery);
  const contextOptions = useMemo(
    () => (screen === "context" ? listContextFiles(props.cwd, fileQuery, 80) : []),
    [fileQuery, props.cwd, screen],
  );
  const allCommandSpecs = useMemo(() => mergeCommandSpecs(SLASH_COMMANDS, customCommands), [customCommands]);
  const paletteOptions = filterSlashCommands(composer.startsWith("/") ? composer : "", allCommandSpecs);
  const visiblePaletteOptions = paletteOptions.slice(0, PALETTE_VISIBLE_LIMIT);
  const visibleSessionOptions = filteredSessionOptions.slice(0, PICKER_VISIBLE_LIMIT);
  const visibleContextOptions = contextOptions.slice(0, PICKER_VISIBLE_LIMIT);
  const detailScreens: TuiScreen[] = ["doctor", "results", "hunt", "init", "tools", "mcp"];
  const showSidebar = width >= 128 && showDetails && detailScreens.includes(screen);
  const mainWidth = Math.max(48, showSidebar ? width - 42 : width - 4);

  useEffect(() => {
    if (!leaderArmed) return;
    const timer = setTimeout(() => setLeaderArmed(false), 2000);
    return () => clearTimeout(timer);
  }, [leaderArmed]);

  useEffect(() => {
    setTranscriptScrollOffset(0);
  }, [visibleMessages.length]);

  useEffect(() => {
    setComposerCursor((cursor) => boundedComposerCursor(composer, cursor));
  }, [composer]);

  useEffect(() => {
    if (!process.stdout.isTTY) return;
    const location = screen === "chat" ? mode : screen;
    const modelText = provider ? `${provider.id}/${model ?? "-"}` : "connect";
    process.stdout.write(`\u001B]0;bugbounty | ${location} | ${modelText}\u0007`);
  }, [mode, model, provider, screen]);

  useInput((input, key) => {
    if (busy) return;
    if (leaderArmed) {
      setLeaderArmed(false);
      handleLeaderInput(input, key);
      return;
    }
    if (isCtrlKey(input, key, "c")) {
      if (screen === "chat" && composer.length > 0) {
        setComposer("");
        setComposerCursor(0);
        resetPromptHistoryCursor();
        setNotice({ kind: "warn", text: "Input cleared. Press Ctrl+C twice on an empty input to exit." });
        return;
      }
      if (exitArmed) {
        exit();
        return;
      }
      setExitArmed(true);
      setNotice({ kind: "warn", text: "Press Ctrl+C again to exit, or /exit." });
      return;
    }
    setExitArmed(false);

    if (isCtrlKey(input, key, "x")) {
      setLeaderArmed(true);
      setNotice({
        kind: "info",
        text: "Leader: n new, h help, l sessions, m models, a mode, i init, d details, c compact, q quit.",
      });
      return;
    }
    if (isCtrlKey(input, key, "t")) {
      toggleThinking();
      return;
    }
    if (isCtrlKey(input, key, "d") && screen === "chat" && composer.length === 0) {
      exit();
      return;
    }
    if (
      input.toLowerCase() === "r" &&
      composer.length === 0 &&
      ["chat", "doctor", "hunt", "results", "init", "tools", "mcp"].includes(screen)
    ) {
      refreshInsight();
      return;
    }
    if (screen === "chat" && handleTranscriptNavigation(input, key)) {
      return;
    }
    if (key.tab) {
      switchMode(key.shift ? previousTuiMode(mode) : nextTuiMode(mode));
      return;
    }
    if (isCtrlKey(input, key, "p")) {
      openScreen("palette");
      setComposer("/");
      setComposerCursor(1);
      return;
    }
    if (screen === "chat" && input === "@") {
      openScreen("context");
      setFileQuery("");
      return;
    }
    if (screen === "chat" && input === "!" && composer.length === 0) {
      openScreen("action");
      return;
    }

    if (screen === "connect") {
      handleConnectInput(input, key);
      return;
    }
    if (screen === "models") {
      handleModelInput(input, key);
      return;
    }
    if (screen === "sessions") {
      handleSessionInput(input, key);
      return;
    }
    if (screen === "palette") {
      handlePaletteInput(input, key);
      return;
    }
    if (screen === "themes") {
      handleThemeInput(input, key);
      return;
    }
    if (screen === "context") {
      handleContextInput(input, key);
      return;
    }
    if (screen === "action") {
      handleActionInput(input, key);
      return;
    }
    handleComposerInput(input, key);
  });

  function openScreen(next: TuiScreen): void {
    setPreviousScreen(screen === "palette" ? previousScreen : screen);
    setScreen(next);
    setSelected(0);
  }

  function openModelsScreen(): void {
    setModelQuery("");
    setComposer("");
    setComposerCursor(0);
    if (configuredModelOptions.length === 0) {
      openScreen("connect");
      setNotice({ kind: "warn", text: "Connect a provider before choosing a model." });
      return;
    }
    openScreen("models");
  }

  function handleLeaderInput(input: string, key: InputKey): void {
    if (key.escape) return;
    if (input === "M" || (input.toLowerCase() === "m" && key.shift)) {
      cycleModel(key.meta ? "previous" : "next");
      return;
    }
    const command = input.toLowerCase();
    if (command === "n") {
      executeSlash("/new", "");
      return;
    }
    if (command === "h") {
      openScreen("help");
      return;
    }
    if (command === "s" || command === "l") {
      openScreen("sessions");
      return;
    }
    if (command === "m") {
      openModelsScreen();
      return;
    }
    if (command === "a") {
      switchMode(nextTuiMode(mode));
      return;
    }
    if (command === "i") {
      refreshInsight();
      openScreen("init");
      return;
    }
    if (command === "d") {
      toggleDetails();
      return;
    }
    if (command === "c") {
      executeSlash("/compact", "");
      return;
    }
    if (command === "e") {
      executeSlash("/editor", "");
      return;
    }
    if (command === "x") {
      executeSlash("/export", "");
      return;
    }
    if (command === "t") {
      openScreen("themes");
      return;
    }
    if (command === "u") {
      executeSlash("/undo", "");
      return;
    }
    if (command === "r") {
      executeSlash("/redo", "");
      return;
    }
    if (command === "q") {
      exit();
      return;
    }
    setNotice({ kind: "warn", text: `Unknown leader key: ${input || "?"}.` });
  }

  function returnToPrevious(): void {
    setScreen(previousScreen === "palette" ? "chat" : previousScreen);
    setSelected(0);
    setComposer("");
  }

  function refreshInsight(): void {
    setInsight(loadWorkspaceInsight(props.cwd));
    setNotice({ kind: "ok", text: "Workspace state refreshed from local .bounty data." });
  }

  function persistSession(patch: Partial<Omit<TuiSessionRecord, "id" | "createdAt">>): void {
    setSession((current) => sessions.update(current.id, patch));
  }

  function switchMode(nextMode: TuiMode): void {
    setMode(nextMode);
    persistSession({ mode: nextMode });
    setNotice({ kind: "ok", text: `Mode switched to ${nextMode}.` });
  }

  function selectModelOption(choice: TuiModelOption, options: { announce?: boolean } = {}): void {
    const nextProvider = providers.find((candidate) => candidate.id === choice.provider);
    setProvider(nextProvider);
    setModel(choice.model);
    setModelQuery("");
    setScreen("chat");
    persistSession({ providerId: choice.provider, model: choice.model });
    const persisted = settingsStore.update({ recentModels: appendRecentModel(recentModels, choice) });
    setRecentModels(persisted.recentModels);
    if (options.announce !== false) {
      setNotice({ kind: "ok", text: `Model switched to ${choice.provider}/${choice.model}.` });
    }
  }

  function cycleModel(direction: "next" | "previous"): void {
    const current = provider && model ? { provider: provider.id, model } : undefined;
    const choice = cycleModelOption(configuredModelOptions, current, direction);
    if (!choice) {
      openModelsScreen();
      setNotice({ kind: "warn", text: "Connect a provider before cycling models." });
      return;
    }
    selectModelOption(choice);
  }

  function replaceMessages(nextMessages: ProviderChatMessage[], options: { undoable?: boolean } = {}): void {
    if (options.undoable) {
      setUndoStack((stack) => [...stack, messages].slice(-25));
      setRedoStack([]);
    }
    setMessages(nextMessages);
    persistSession({ messages: nextMessages });
  }

  function undoTranscript(): void {
    const previous = undoStack[undoStack.length - 1];
    if (!previous) {
      setNotice({ kind: "warn", text: "Nothing to undo in this session." });
      return;
    }
    setUndoStack((stack) => stack.slice(0, -1));
    setRedoStack((stack) => [...stack, messages].slice(-25));
    setMessages(previous);
    persistSession({ messages: previous });
    setScreen("chat");
    setNotice({ kind: "ok", text: "Undid the last local transcript change." });
  }

  function redoTranscript(): void {
    const next = redoStack[redoStack.length - 1];
    if (!next) {
      setNotice({ kind: "warn", text: "Nothing to redo in this session." });
      return;
    }
    setRedoStack((stack) => stack.slice(0, -1));
    setUndoStack((stack) => [...stack, messages].slice(-25));
    setMessages(next);
    persistSession({ messages: next });
    setScreen("chat");
    setNotice({ kind: "ok", text: "Redid the transcript change." });
  }

  function exportSessionMarkdown(): void {
    try {
      const file = writeSessionExport(props.cwd, session, messages);
      setNotice({ kind: "ok", text: `Session exported: ${path.relative(props.cwd, file)}` });
      setScreen("chat");
    } catch (error) {
      setNotice({ kind: "error", text: errorMessage(error) });
    }
  }

  function startNewSession(): void {
    const next = sessions.create({
      providerId: provider?.id,
      model,
      mode,
      messages: [{ role: "system", content: props.systemPrompt }],
    });
    setSession(next);
    setMessages(next.messages);
    resetPromptHistoryCursor();
    setContextFiles([]);
    setUndoStack([]);
    setRedoStack([]);
    setScreen("chat");
    setNotice({ kind: "ok", text: "New local session started." });
  }

  function handleConnectInput(input: string, key: InputKey): void {
    const catalog = providerOptions;
    if (connectStage === "provider") {
      if (key.backspace || key.delete) {
        setProviderQuery((value) => value.slice(0, -1));
        setSelected(0);
        return;
      }
      if (key.downArrow) {
        if (catalog.length === 0) return;
        const next = (selected + 1) % catalog.length;
        setSelected(next);
        setPendingProvider(catalog[next]);
        return;
      }
      if (key.upArrow) {
        if (catalog.length === 0) return;
        const next = (selected - 1 + catalog.length) % catalog.length;
        setSelected(next);
        setPendingProvider(catalog[next]);
        return;
      }
      if (key.escape && providerQuery) {
        setProviderQuery("");
        setSelected(0);
        return;
      }
      if (key.escape && provider) {
        setScreen("chat");
        return;
      }
      if (key.return) {
        const choice = catalog[selected];
        if (!choice) {
          setNotice({ kind: "warn", text: `No provider matches "${providerQuery}".` });
          return;
        }
        setPendingProvider(choice);
        if (choice.type === "local") {
          connectProvider(choice, "");
          return;
        }
        setConnectStage("api-key");
        setApiKey("");
        setNotice({ kind: "info", text: `Paste API key for ${choice.displayName}, then press Enter.` });
        return;
      }
      appendPrintable(input, key, (updater) => {
        setProviderQuery(updater);
        setSelected(0);
      });
      return;
    }

    if (key.escape) {
      setConnectStage("provider");
      setApiKey("");
      return;
    }
    if (key.backspace || key.delete) {
      setApiKey((value) => value.slice(0, -1));
      return;
    }
    if (key.return) {
      if (!pendingProvider) return;
      connectProvider(pendingProvider, apiKey);
      return;
    }
    appendPrintable(input, key, setApiKey);
  }

  function connectProvider(choice: ProviderCatalogEntry, keyValue: string): void {
    try {
      const result = manager.connect({
        id: choice.id,
        apiKey: choice.type === "local" ? undefined : keyValue.trim(),
        local: choice.type === "local",
        model: choice.defaultModel,
      });
      const nextProviders = manager.list();
      setProviders(nextProviders);
      setProvider(result.provider);
      setModel(result.provider.model);
      if (result.provider.model) {
        const persisted = settingsStore.update({ recentModels: appendRecentModel(recentModels, { provider: result.provider.id, model: result.provider.model }) });
        setRecentModels(persisted.recentModels);
      }
      setApiKey("");
      setConnectStage("provider");
      setProviderQuery("");
      setScreen("chat");
      persistSession({ providerId: result.provider.id, model: result.provider.model });
      setNotice({
        kind: result.provider.status === "configured" ? "ok" : "warn",
        text: result.provider.status === "configured" ? `Connected ${result.provider.id}/${result.provider.model}.` : result.provider.message,
      });
    } catch (error) {
      setNotice({ kind: "error", text: errorMessage(error) });
    }
  }

  function handleModelInput(input: string, key: InputKey): void {
    if (key.escape) {
      if (modelQuery) {
        setModelQuery("");
        setSelected(0);
        return;
      }
      setScreen("chat");
      return;
    }
    if (configuredModelOptions.length === 0) {
      setScreen("connect");
      return;
    }
    if (key.backspace || key.delete) {
      setModelQuery((value) => value.slice(0, -1));
      setSelected(0);
      return;
    }
    if (key.downArrow) {
      if (visibleModelOptions.length === 0) return;
      setSelected((selected + 1) % visibleModelOptions.length);
      return;
    }
    if (key.upArrow) {
      if (visibleModelOptions.length === 0) return;
      setSelected((selected - 1 + visibleModelOptions.length) % visibleModelOptions.length);
      return;
    }
    if (key.return) {
      const choice = visibleModelOptions[selected];
      if (!choice) {
        setNotice({ kind: "warn", text: `No model matches "${modelQuery}".` });
        return;
      }
      selectModelOption(choice);
      return;
    }
    if (input === "/") {
      openScreen("palette");
      setComposer("/");
      setComposerCursor(1);
      return;
    }
    appendPrintable(input, key, (updater) => {
      setModelQuery(updater);
      setSelected(0);
    });
  }

  function handleSessionInput(input: string, key: InputKey): void {
    if (key.escape) {
      if (sessionQuery) {
        setSessionQuery("");
        setSelected(0);
        return;
      }
      setScreen("chat");
      return;
    }
    if (key.backspace || key.delete) {
      setSessionQuery((value) => value.slice(0, -1));
      setSelected(0);
      return;
    }
    if (visibleSessionOptions.length === 0) {
      if (input === "/" && !sessionQuery) {
        openScreen("palette");
        setComposer("/");
        setComposerCursor(1);
        return;
      }
      appendPrintable(input, key, (updater) => {
        setSessionQuery(updater);
        setSelected(0);
      });
      return;
    }
    if (key.downArrow) {
      setSelected((selected + 1) % visibleSessionOptions.length);
      return;
    }
    if (key.upArrow) {
      setSelected((selected - 1 + visibleSessionOptions.length) % visibleSessionOptions.length);
      return;
    }
    if (key.return) {
      const choice = visibleSessionOptions[selected]!;
      const loaded = sessions.read(choice.id);
      setSession(loaded);
      setMessages(loaded.messages);
      setMode(loaded.mode);
      setPromptHistory(promptHistoryFromMessages(loaded.messages));
      resetPromptHistoryCursor();
      setUndoStack([]);
      setRedoStack([]);
      setProvider(providers.find((candidate) => candidate.id === loaded.providerId));
      setModel(loaded.model);
      setScreen("chat");
      setNotice({ kind: "ok", text: `Resumed ${loaded.title}.` });
      return;
    }
    if (input === "/" && !sessionQuery) {
      openScreen("palette");
      setComposer("/");
      setComposerCursor(1);
      return;
    }
    appendPrintable(input, key, (updater) => {
      setSessionQuery(updater);
      setSelected(0);
    });
  }

  function handlePaletteInput(input: string, key: InputKey): void {
    if (key.escape) {
      returnToPrevious();
      return;
    }
    if (key.backspace || key.delete) {
      setComposer((value) => (value.length <= 1 ? "/" : value.slice(0, -1)));
      setSelected(0);
      return;
    }
    if (key.downArrow) {
      setSelected((selected + 1) % Math.max(1, visiblePaletteOptions.length));
      return;
    }
    if (key.upArrow) {
      setSelected((selected - 1 + Math.max(1, visiblePaletteOptions.length)) % Math.max(1, visiblePaletteOptions.length));
      return;
    }
    if (key.return) {
      const command = visiblePaletteOptions[selected];
      if (!command) {
        setNotice({ kind: "warn", text: `No command matches ${composer}.` });
        return;
      }
      executeSlash(command.id, "");
      return;
    }
    appendPrintable(input, key, (updater) => {
      setComposer((value) => {
        const next = updater(value);
        const query = next.startsWith("/") ? next : `/${next}`;
        setComposerCursor(query.length);
        return query;
      });
      setSelected(0);
    });
  }

  function handleThemeInput(input: string, key: InputKey): void {
    if (key.escape) {
      setScreen("chat");
      return;
    }
    if (key.downArrow) {
      setSelected((selected + 1) % TUI_THEMES.length);
      return;
    }
    if (key.upArrow) {
      setSelected((selected - 1 + TUI_THEMES.length) % TUI_THEMES.length);
      return;
    }
    if (key.return) {
      const selectedTheme = TUI_THEMES[selected]!;
      const persisted = settingsStore.update({ theme: selectedTheme.id });
      setThemeId(persisted.theme);
      setShowDetails(persisted.details);
      setShowThinking(persisted.thinking);
      setScreen("chat");
      setNotice({ kind: "ok", text: `Theme switched to ${selectedTheme.name}.` });
      return;
    }
  }

  function handleContextInput(input: string, key: InputKey): void {
    if (key.escape) {
      setScreen("chat");
      setFileQuery("");
      return;
    }
    if (key.backspace || key.delete) {
      setFileQuery((value) => value.slice(0, -1));
      setSelected(0);
      return;
    }
    if (key.downArrow) {
      setSelected((selected + 1) % Math.max(1, visibleContextOptions.length));
      return;
    }
    if (key.upArrow) {
      setSelected((selected - 1 + Math.max(1, visibleContextOptions.length)) % Math.max(1, visibleContextOptions.length));
      return;
    }
    if (key.return) {
      const chosen = visibleContextOptions[selected];
      if (!chosen) return;
      const nextFiles = [...new Set([...contextFiles, chosen.path])].slice(-8);
      setContextFiles(nextFiles);
      persistSession({ contextFiles: nextFiles });
      const nextComposer = safeComposerAppend(composer, `${composer.endsWith(" ") || !composer ? "" : " "}@${chosen.path} `);
      setComposer(nextComposer);
      setComposerCursor(nextComposer.length);
      setScreen("chat");
      setFileQuery("");
      setNotice({ kind: "ok", text: `Attached @${chosen.path}.` });
      return;
    }
    appendPrintable(input, key, (updater) => {
      setFileQuery(updater);
      setSelected(0);
    });
  }

  function handleActionInput(input: string, key: InputKey): void {
    if (key.escape) {
      setScreen("chat");
      return;
    }
    if (key.downArrow) {
      setSelected((selected + 1) % SAFE_ACTIONS.length);
      return;
    }
    if (key.upArrow) {
      setSelected((selected - 1 + SAFE_ACTIONS.length) % SAFE_ACTIONS.length);
      return;
    }
    if (key.return) {
      const action = SAFE_ACTIONS[selected]!;
      const nextMessages = [
        ...messages,
        {
          role: "assistant" as const,
          content: [`Planned safe action: ${action.title}`, `$ ${action.command}`, action.note].join("\n"),
        },
      ];
      setMessages(nextMessages);
      persistSession({ messages: nextMessages });
      setScreen("chat");
      setNotice({ kind: "ok", text: "Action planned only. Review and run manually when authorized." });
    }
  }

  function handleComposerInput(input: string, key: InputKey): void {
    if (key.escape) {
      setComposer("");
      setScreen("chat");
      resetPromptHistoryCursor();
      return;
    }
    if (key.upArrow) {
      if (recallPromptHistory("older")) return;
    }
    if (key.downArrow) {
      if (recallPromptHistory("newer")) return;
    }
    if (key.leftArrow || isCtrlKey(input, key, "b")) {
      setComposerCursor((cursor) => Math.max(0, cursor - 1));
      return;
    }
    if (key.rightArrow || isCtrlKey(input, key, "f")) {
      setComposerCursor((cursor) => Math.min(composer.length, cursor + 1));
      return;
    }
    if (key.home || isCtrlKey(input, key, "a")) {
      setComposerCursor(0);
      return;
    }
    if (key.end || isCtrlKey(input, key, "e")) {
      setComposerCursor(composer.length);
      return;
    }
    if (isCtrlKey(input, key, "u")) {
      setComposer("");
      setComposerCursor(0);
      resetPromptHistoryCursor();
      setNotice({ kind: "info", text: "Input cleared." });
      return;
    }
    if (isCtrlKey(input, key, "w")) {
      applyComposerEdit(killComposerWordBeforeCursor(composer, composerCursor));
      resetPromptHistoryCursor();
      return;
    }
    if (isCtrlKey(input, key, "k")) {
      applyComposerEdit(killComposerAfterCursor(composer, composerCursor));
      resetPromptHistoryCursor();
      return;
    }
    if (key.backspace) {
      applyComposerEdit(backspaceComposerText(composer, composerCursor));
      resetPromptHistoryCursor();
      return;
    }
    if (key.delete) {
      applyComposerEdit(deleteComposerText(composer, composerCursor));
      resetPromptHistoryCursor();
      return;
    }
    if (isComposerNewline(input, key)) {
      applyComposerEdit(insertComposerText(composer, composerCursor, "\n"));
      resetPromptHistoryCursor();
      return;
    }
    if (key.return) {
      const value = composer.trim();
      setComposer("");
      setComposerCursor(0);
      if (!value) return;
      rememberPrompt(value);
      const slash = parseSlashCommand(value);
      if (slash) {
        executeSlash(slash.command, slash.args);
        return;
      }
      void sendMessage(value);
      return;
    }
    if (composer.length === 0 && input === "/") {
      openScreen("palette");
      setComposer("/");
      setComposerCursor(1);
      resetPromptHistoryCursor();
      return;
    }
    resetPromptHistoryCursor();
    if (!input || key.ctrl || key.meta || key.return || key.tab || key.escape) return;
    applyComposerEdit(insertComposerText(composer, composerCursor, input));
  }

  function executeSlash(command: string, args: string): void {
    const spec = SLASH_COMMANDS.find((candidate) => candidate.id === command);
    const customCommand = customCommands.find((candidate) => candidate.id === command);
    if (command === "/exit" || command === "/quit" || command === "/q") {
      exit();
      return;
    }
    if (command === "/clear") command = "/new";
    if (command === "/compact" || command === "/summarize") {
      const compacted = trimMessages(messages);
      replaceMessages(compacted, { undoable: true });
      setScreen("chat");
      setNotice({ kind: "ok", text: "Session compacted to recent context." });
      return;
    }
    if (command === "/undo") {
      undoTranscript();
      return;
    }
    if (command === "/redo") {
      redoTranscript();
      return;
    }
    if (command === "/export") {
      exportSessionMarkdown();
      return;
    }
    if (command === "/share" || command === "/unshare") {
      setScreen("chat");
      setNotice({ kind: "warn", text: "Sharing is disabled: BountyPilot stays local-first and does not publish sessions." });
      return;
    }
    if (command === "/editor") {
      setScreen("chat");
      setNotice({ kind: "info", text: process.env.EDITOR ? `External editor configured: ${process.env.EDITOR}.` : "Set EDITOR to enable external compose flow." });
      return;
    }
    if (command === "/details") {
      toggleDetails();
      return;
    }
    if (command === "/mode" || command === "/agent" || command === "/agents") {
      const requestedMode = args.toLowerCase() as TuiMode;
      if (isTuiMode(requestedMode)) {
        switchMode(requestedMode);
      } else {
        switchMode(nextTuiMode(mode));
      }
      setScreen("chat");
      return;
    }
    if (command === "/model" || command === "/models") {
      const normalizedArgs = args.toLowerCase();
      if (normalizedArgs === "next") {
        cycleModel("next");
        return;
      }
      if (normalizedArgs === "prev" || normalizedArgs === "previous") {
        cycleModel("previous");
        return;
      }
    }
    if (command === "/thinking") {
      toggleThinking();
      return;
    }
    if (command === "/new") {
      startNewSession();
      return;
    }
    if (command === "/doctor") {
      refreshInsight();
      setScreen("doctor");
      setNotice({
        kind: providers.some((candidate) => candidate.status === "configured") ? "ok" : "warn",
        text: providerDoctorLine(providers),
      });
      return;
    }
    if (command === "/recon") {
      refreshInsight();
      setScreen("hunt");
      setNotice({ kind: "info", text: args ? `Dry-run recon target queued in panel: ${args}` : "Use hunt panel commands in dry-run first." });
      return;
    }
    if (command === "/resume" || command === "/continue") {
      setScreen("sessions");
      setSelected(0);
      setSessionQuery("");
      setComposer("");
      setComposerCursor(0);
      return;
    }
    if (spec?.screen) {
      if (spec.screen === "models") {
        openModelsScreen();
        return;
      }
      if (["hunt", "results", "doctor", "init", "tools", "mcp"].includes(spec.screen)) {
        refreshInsight();
      }
      setScreen(spec.screen);
      setSelected(0);
      setComposer("");
      setComposerCursor(0);
      return;
    }
    if (customCommand) {
      runCustomCommand(customCommand, args);
      return;
    }
    setScreen("chat");
    setNotice({ kind: "warn", text: `Unknown command: ${command}` });
  }

  function runCustomCommand(command: TuiCustomCommand, args: string): void {
    const prompt = renderCustomCommandPrompt(command, args);
    if (!prompt) {
      setNotice({ kind: "warn", text: `${command.id} has no prompt body.` });
      return;
    }
    if (!provider || !model) {
      setComposer(prompt);
      setComposerCursor(prompt.length);
      setScreen("chat");
      setNotice({ kind: "warn", text: `${command.id} loaded into composer. Connect a provider to send it.` });
      return;
    }
    setScreen("chat");
    setNotice({ kind: "info", text: `Running ${command.id} from ${command.sourcePath}.` });
    void sendMessage(prompt);
  }

  function toggleDetails(): void {
    const persisted = settingsStore.update({ details: !showDetails });
    setShowDetails(persisted.details);
    setShowThinking(persisted.thinking);
    setThemeId(persisted.theme);
    setNotice({
      kind: "ok",
      text: persisted.details ? "Details enabled for dashboards and actions." : "Details collapsed for a cleaner cockpit.",
    });
  }

  function toggleThinking(): void {
    const persisted = settingsStore.update({ thinking: !showThinking });
    setShowThinking(persisted.thinking);
    setShowDetails(persisted.details);
    setThemeId(persisted.theme);
    setNotice({
      kind: "ok",
      text: persisted.thinking ? "Thinking display enabled." : "Thinking display hidden.",
    });
  }

  async function sendMessage(text: string): Promise<void> {
    if (!provider || !model) {
      setScreen("connect");
      setNotice({ kind: "warn", text: "Connect a provider before chatting." });
      return;
    }
    const nextMessages = trimMessages([...messages, { role: "user", content: text }]);
    const contextPrompt = safeContextPrompt(props.cwd, contextFiles);
    const providerMessages = contextPrompt
      ? trimMessages([...messages, { role: "user", content: `${text}\n\n${contextPrompt}` }])
      : nextMessages;
    setUndoStack((stack) => [...stack, messages].slice(-25));
    setRedoStack([]);
    setMessages(nextMessages);
    persistSession({ messages: nextMessages, providerId: provider.id, model, mode });
    setBusy(true);
    setNotice({ kind: "info", text: `${provider.id}/${model} thinking...` });
    try {
      const result = await client.complete({
        providerId: provider.id,
        model,
        messages: withModeContext(providerMessages, mode, showThinking),
        temperature: props.temperature,
        maxTokens: props.maxTokens,
      });
      const finalMessages = trimMessages([...nextMessages, { role: "assistant", content: result.message }]);
      setMessages(finalMessages);
      persistSession({ messages: finalMessages, providerId: provider.id, model, mode });
      setNotice({ kind: "ok", text: `Response received from ${provider.id}/${model}.` });
    } catch (error) {
      const finalMessages = [...nextMessages, { role: "assistant" as const, content: `Provider error: ${errorMessage(error)}` }];
      setMessages(finalMessages);
      persistSession({ messages: finalMessages, providerId: provider.id, model, mode });
      setNotice({ kind: "error", text: errorMessage(error) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box flexDirection="column" height={height} width={width}>
      <Box flexGrow={1} flexDirection={showSidebar ? "row" : "column"} paddingX={2}>
        <Box flexDirection="column" flexGrow={1} width={showSidebar ? mainWidth : undefined}>
          {(screen === "chat" || isOverlayScreen(screen)) && (
            <Transcript
              messages={transcriptWindow.items}
              title={sessionTitleFromMessages(visibleMessages)}
              metrics={formatTranscriptTitleMetrics(visibleMessages)}
              contextFiles={contextFiles}
              width={mainWidth}
              scrollOffset={transcriptWindow.offset}
              hasOlder={transcriptWindow.hasOlder}
              hasNewer={transcriptWindow.hasNewer}
              totalMessages={visibleMessages.length}
              theme={theme}
            />
          )}
          {isOverlayScreen(screen) && (
            <OverlaySurface theme={theme}>
              {screen === "connect" && (
                <ConnectScreen
                  catalog={providerOptions}
                  query={providerQuery}
                  selected={selected}
                  stage={connectStage}
                  pendingProvider={pendingProvider}
                  apiKey={apiKey}
                  theme={theme}
                />
              )}
              {screen === "models" && (
                <ModelScreen
                  options={visibleModelOptions}
                  totalMatches={modelOptions.length}
                  hasAny={configuredModelOptions.length > 0}
                  selected={selected}
                  query={modelQuery}
                  theme={theme}
                />
              )}
              {screen === "sessions" && (
                <SessionScreen
                  sessions={visibleSessionOptions}
                  totalSessions={sessionOptions.length}
                  totalMatches={filteredSessionOptions.length}
                  query={sessionQuery}
                  selected={selected}
                  theme={theme}
                />
              )}
              {screen === "palette" && (
                <PaletteScreen commands={visiblePaletteOptions} totalCommands={paletteOptions.length} selected={selected} query={composer} theme={theme} />
              )}
              {screen === "themes" && <ThemeScreen selected={selected} current={themeId} theme={theme} />}
              {screen === "context" && <ContextScreen files={visibleContextOptions} selected={selected} query={fileQuery} attached={contextFiles} theme={theme} />}
              {screen === "action" && <ActionScreen selected={selected} theme={theme} />}
              {screen === "help" && <HelpPanel providers={providers} customCommands={customCommands} theme={theme} />}
            </OverlaySurface>
          )}
          {!isOverlayScreen(screen) && screen === "doctor" && <DoctorPanel providers={providers} insight={insight} theme={theme} />}
          {!isOverlayScreen(screen) && screen === "results" && <ResultsPanel insight={insight} theme={theme} />}
          {!isOverlayScreen(screen) && screen === "hunt" && <HuntPanel provider={provider} model={model} insight={insight} theme={theme} />}
          {!isOverlayScreen(screen) && screen === "init" && <InitPanel providers={providers} insight={insight} theme={theme} />}
          {!isOverlayScreen(screen) && screen === "tools" && <ToolsPanel insight={insight} showDetails={showDetails} theme={theme} />}
          {!isOverlayScreen(screen) && screen === "mcp" && <McpPanel insight={insight} showDetails={showDetails} theme={theme} />}
        </Box>
        {showSidebar && (
          <Box width={34} marginLeft={2} flexDirection="column">
            <MetaPanel
              providers={providers}
              session={session}
              mode={mode}
              contextFiles={contextFiles}
              insight={insight}
              showDetails={showDetails}
              showThinking={showThinking}
              theme={theme}
            />
          </Box>
        )}
      </Box>
      {composer.startsWith("/") && screen === "chat" && <InlineCommandHints commands={filterSlashCommands(composer, allCommandSpecs).slice(0, 5)} theme={theme} />}
      <NoticeBar notice={notice} busy={busy} theme={theme} />
      <Composer
        value={screen === "connect" && connectStage === "api-key" ? maskedInput(apiKey) : composer}
        cursor={screen === "connect" && connectStage === "api-key" ? apiKey.length : composerCursor}
        screen={screen}
        connectStage={connectStage}
        mode={mode}
        provider={provider}
        model={model}
        modelLabelOverride={props.demoSession && !provider ? "Claude Opus 4.5" : undefined}
        theme={theme}
      />
      <FooterLine
        mode={mode}
        leaderArmed={leaderArmed}
        theme={theme}
      />
    </Box>
  );

  function appendPrintable(
    input: string,
    key: InputKey,
    setter: (updater: (value: string) => string) => void,
  ): void {
    if (!input || key.ctrl || key.meta || key.return || key.tab || key.escape) return;
    setter((value) => safeComposerAppend(value, input));
  }

  function applyComposerEdit(edit: { value: string; cursor: number }): void {
    setComposer(edit.value);
    setComposerCursor(edit.cursor);
  }

  function handleTranscriptNavigation(input: string, key: InputKey): boolean {
    if (key.pageUp) {
      setTranscriptScrollOffset((offset) => offset + transcriptLimit);
      setNotice({ kind: "info", text: "Scrolled transcript up. End jumps to newest." });
      return true;
    }
    if (key.pageDown) {
      setTranscriptScrollOffset((offset) => Math.max(0, offset - transcriptLimit));
      setNotice({ kind: "info", text: "Scrolled transcript down." });
      return true;
    }
    if (composer.length > 0 && (key.home || key.end)) return false;
    if (key.home || isCtrlKey(input, key, "g")) {
      setTranscriptScrollOffset(Math.max(0, visibleMessages.length - transcriptLimit));
      setNotice({ kind: "info", text: "Jumped to the first visible message." });
      return true;
    }
    if (key.end) {
      setTranscriptScrollOffset(0);
      setNotice({ kind: "info", text: "Jumped to the newest message." });
      return true;
    }
    return false;
  }

  function rememberPrompt(value: string): void {
    setPromptHistory((history) => appendPromptHistory(history, value));
    resetPromptHistoryCursor();
  }

  function resetPromptHistoryCursor(): void {
    setHistoryCursor(undefined);
    setHistoryDraft("");
  }

  function recallPromptHistory(direction: "older" | "newer"): boolean {
    if (promptHistory.length === 0) return false;
    if (direction === "older") {
      const nextCursor = historyCursor === undefined ? promptHistory.length - 1 : Math.max(0, historyCursor - 1);
      if (historyCursor === undefined) setHistoryDraft(composer);
      const nextPrompt = promptHistory[nextCursor] ?? "";
      setHistoryCursor(nextCursor);
      setComposer(nextPrompt);
      setComposerCursor(nextPrompt.length);
      setNotice({ kind: "info", text: `Prompt history ${nextCursor + 1}/${promptHistory.length}.` });
      return true;
    }
    if (historyCursor === undefined) return false;
    const nextCursor = historyCursor + 1;
    if (nextCursor >= promptHistory.length) {
      setHistoryCursor(undefined);
      setComposer(historyDraft);
      setComposerCursor(historyDraft.length);
      setHistoryDraft("");
      setNotice({ kind: "info", text: "Returned to current draft." });
      return true;
    }
    const nextPrompt = promptHistory[nextCursor] ?? "";
    setHistoryCursor(nextCursor);
    setComposer(nextPrompt);
    setComposerCursor(nextPrompt.length);
    setNotice({ kind: "info", text: `Prompt history ${nextCursor + 1}/${promptHistory.length}.` });
    return true;
  }
}

function isOverlayScreen(screen: TuiScreen): boolean {
  return screen === "connect" ||
    screen === "models" ||
    screen === "sessions" ||
    screen === "palette" ||
    screen === "themes" ||
    screen === "context" ||
    screen === "action" ||
    screen === "help";
}

function OverlaySurface(input: { children: React.ReactNode; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text color={input.theme.muted}>.........</Text>
      <Box flexDirection="row">
        <Box flexDirection="column">
          <Text color={input.theme.accent}>│</Text>
        </Box>
        <Box flexDirection="column" marginLeft={1} flexGrow={1}>
          {input.children}
        </Box>
      </Box>
    </Box>
  );
}

function ConnectScreen(input: {
  catalog: ProviderCatalogEntry[];
  query: string;
  selected: number;
  stage: ConnectStage;
  pendingProvider?: ProviderCatalogEntry;
  apiKey: string;
  theme: TuiTheme;
}): React.ReactNode {
  if (input.stage === "api-key") {
    return (
      <Box flexDirection="column" paddingTop={1}>
        <Text>
          <Text color={input.theme.accent} bold>/connect</Text>
          <Text color={input.theme.muted}>  {input.pendingProvider?.displayName}</Text>
        </Text>
        <Box marginTop={1}>
          <Text color={input.theme.secondary}>api key </Text>
          <Text>{maskedInput(input.apiKey) || "_"}</Text>
        </Box>
      </Box>
    );
  }
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>/connect</Text>
      <Box marginTop={1}>
        <Text color={input.theme.secondary}>search </Text>
        <Text>{input.query || "_"}</Text>
      </Box>
      <Box flexDirection="column" marginTop={1}>
        {input.catalog.length === 0 ? (
          <Text color={input.theme.warning}>No matching providers.</Text>
        ) : (
          input.catalog.map((provider, index) => (
            <SelectorRow
              key={provider.id}
              selected={index === input.selected}
              label={provider.displayName}
              detail={`${provider.defaultModel ?? provider.models[0] ?? "-"}  ${provider.id}`}
              theme={input.theme}
            />
          ))
        )}
      </Box>
    </Box>
  );
}

function ModelScreen(input: {
  options: Array<{ provider: string; model: string; selected: boolean }>;
  totalMatches: number;
  hasAny: boolean;
  selected: number;
  query: string;
  theme: TuiTheme;
}): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>/models</Text>
      <Box marginTop={1}>
        <Text color={input.theme.secondary}>search </Text>
        <Text>{input.query || "_"}</Text>
      </Box>
      <Box flexDirection="column" marginTop={1}>
        {input.options.length === 0 ? (
          <>
            <Text color={input.theme.warning}>{input.hasAny ? "No matching models." : "No configured models."}</Text>
          </>
        ) : (
          <>
            <Text color={input.theme.warning}>configured</Text>
            {input.options.map((option, index) => (
              <SelectorRow
                key={`${option.provider}/${option.model}`}
                selected={index === input.selected}
                label={displayModelLabel(option.provider, option.model)}
                detail={`${option.provider}/${option.model}${option.selected ? "  current" : ""}`}
                theme={input.theme}
              />
            ))}
            {input.totalMatches > input.options.length && (
              <Text color={input.theme.muted}>  {input.totalMatches - input.options.length} more</Text>
            )}
          </>
        )}
      </Box>
    </Box>
  );
}

function SessionScreen(input: {
  sessions: TuiSessionSummary[];
  totalSessions: number;
  totalMatches: number;
  query: string;
  selected: number;
  theme: TuiTheme;
}): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /sessions
      </Text>
      <Box marginTop={1}>
        <Text color={input.theme.secondary}>search </Text>
        <Text>{input.query || "_"}</Text>
      </Box>
      <Box flexDirection="column" marginTop={1}>
        {input.sessions.length === 0 ? (
          <>
            <Text color={input.theme.warning}>{input.totalSessions === 0 ? "No saved sessions yet." : "No matching sessions."}</Text>
          </>
        ) : (
          <>
            {input.sessions.map((session, index) => (
              <SelectorRow
                key={session.id}
                selected={index === input.selected}
                label={session.title}
                detail={`${session.messages} messages  ${session.providerId ?? "no-provider"}/${session.model ?? "-"}  ${session.mode}`}
                theme={input.theme}
              />
            ))}
            {input.totalMatches > input.sessions.length && (
              <Text color={input.theme.muted}>  {input.totalMatches - input.sessions.length} more</Text>
            )}
          </>
        )}
      </Box>
    </Box>
  );
}

function PaletteScreen(input: { commands: SlashCommandSpec[]; totalCommands: number; selected: number; query: string; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        / commands
      </Text>
      <Box marginTop={1}>
        <Text color={input.theme.secondary}>/ </Text>
        <Text>{input.query.replace(/^\//, "") || "_"}</Text>
      </Box>
      <Box flexDirection="column" marginTop={1}>
        {input.commands.length === 0 ? (
          <Text color={input.theme.warning}>No matching commands.</Text>
        ) : (
          <>
            {input.commands.map((command, index) => (
              <CommandSelectorRow
                key={command.id}
                selected={index === input.selected}
                command={command}
                theme={input.theme}
              />
            ))}
            {input.totalCommands > input.commands.length && (
              <Text color={input.theme.muted}>  {input.totalCommands - input.commands.length} more</Text>
            )}
          </>
        )}
      </Box>
    </Box>
  );
}

function ThemeScreen(input: { selected: number; current: TuiThemeId; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /themes
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {TUI_THEMES.map((theme, index) => (
          <SelectorRow
            key={theme.id}
            selected={index === input.selected}
            label={theme.name}
            detail={`${theme.id === input.current ? "current" : "available"}  ${theme.description}`}
            theme={input.theme}
          />
        ))}
      </Box>
    </Box>
  );
}

function ContextScreen(input: {
  files: ContextFileEntry[];
  selected: number;
  query: string;
  attached: string[];
  theme: TuiTheme;
}): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        @ context
      </Text>
      <Box marginTop={1}>
        <Text color={input.theme.secondary}>@ </Text>
        <Text>{input.query || "_"}</Text>
      </Box>
      {input.attached.length > 0 && (
        <Text color={input.theme.muted}>attached: {input.attached.map((file) => `@${file}`).join(" ")}</Text>
      )}
      <Box flexDirection="column" marginTop={1}>
        {input.files.length === 0 ? (
          <Text color={input.theme.warning}>No matching files.</Text>
        ) : (
          input.files.map((file, index) => (
            <SelectorRow
              key={file.path}
              selected={index === input.selected}
              label={`@${file.path}`}
              detail={`${file.kind}  ${formatBytes(file.size)}`}
              theme={input.theme}
            />
          ))
        )}
      </Box>
    </Box>
  );
}

function ActionScreen(input: { selected: number; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        ! safe action planner
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {SAFE_ACTIONS.map((action, index) => (
          <SelectorRow
            key={action.title}
            selected={index === input.selected}
            label={action.title}
            detail={action.command}
            theme={input.theme}
          />
        ))}
      </Box>
    </Box>
  );
}

function DoctorPanel(input: { providers: ProviderSummary[]; insight: TuiWorkspaceInsight; theme: TuiTheme }): React.ReactNode {
  const readyProviders = input.providers.filter((provider) => provider.status === "configured").length;
  const statusColor =
    input.insight.status === "ready" ? input.theme.success : input.insight.status === "blocked" ? input.theme.error : input.theme.warning;
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /doctor
      </Text>
      <Text color={statusColor}>{input.insight.message}</Text>
      <Box marginTop={1} flexDirection="column">
        <MetricLine label="program" value={input.insight.program ?? "not imported"} theme={input.theme} />
        <MetricLine label="scope" value={`${input.insight.scope.in} in / ${input.insight.scope.out} out`} theme={input.theme} />
        <MetricLine label="providers" value={`${readyProviders}/${input.providers.length} ready`} theme={input.theme} />
        <MetricLine label="jobs" value={`${input.insight.jobs.total} total, ${input.insight.jobs.running} running, ${input.insight.jobs.failed} failed`} theme={input.theme} />
        <MetricLine label="actions" value={`${input.insight.actions.pending} pending, ${input.insight.actions.approved} approved`} theme={input.theme} />
        <MetricLine label="findings" value={`${input.insight.findings.total} total, ${input.insight.findings.ready} report-ready`} theme={input.theme} />
        <MetricLine label="candidates" value={`${input.insight.candidates.total} total, ${input.insight.candidates.needsReview} need review`} theme={input.theme} />
        <MetricLine label="evidence" value={`${input.insight.evidence.total} artifacts`} theme={input.theme} />
        <MetricLine label="recon" value={`${input.insight.recon.inScope}/${input.insight.recon.total} in-scope observations`} theme={input.theme} />
      </Box>
      <NextSteps steps={input.insight.next} theme={input.theme} />
    </Box>
  );
}

function ResultsPanel(input: { insight: TuiWorkspaceInsight; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /results
      </Text>
      <Box marginTop={1} flexDirection="column">
        <MetricLine label="findings" value={`${input.insight.findings.total}`} theme={input.theme} />
        <MetricLine label="candidates" value={`${input.insight.candidates.total}`} theme={input.theme} />
        <MetricLine label="draftable" value={`${input.insight.candidates.ready}`} theme={input.theme} />
        <MetricLine label="ready" value={`${input.insight.findings.ready}`} theme={input.theme} />
        <MetricLine label="best score" value={`${input.insight.findings.bestScore}/100`} theme={input.theme} />
        <MetricLine label="evidence" value={`${input.insight.evidence.total}`} theme={input.theme} />
        <MetricLine label="recon" value={`${input.insight.recon.inScope} in-scope`} theme={input.theme} />
      </Box>
      {input.insight.candidates.top ? (
        <Box marginTop={1} flexDirection="column">
          <Text color={input.theme.secondary}>top candidate</Text>
          <Text>{input.insight.candidates.top.title}</Text>
          <Text color={input.theme.muted}>
            {input.insight.candidates.top.severity}  {input.insight.candidates.top.reportability}  {input.insight.candidates.top.id}
          </Text>
        </Box>
      ) : input.insight.findings.top ? (
        <Box marginTop={1} flexDirection="column">
          <Text color={input.theme.secondary}>top finding</Text>
          <Text>{input.insight.findings.top.title}</Text>
          <Text color={input.theme.muted}>
            {input.insight.findings.top.severity}  score {input.insight.findings.top.score}/100  {input.insight.findings.top.id}
          </Text>
        </Box>
      ) : (
        <Text color={input.theme.warning}>No finding candidates yet. Run /hunt and start with dry-run recon.</Text>
      )}
      <NextSteps steps={input.insight.next} theme={input.theme} />
    </Box>
  );
}

function HuntPanel(input: { provider?: ProviderSummary; model?: string; insight: TuiWorkspaceInsight; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        hunt panel
      </Text>
      <Box marginTop={1} flexDirection="column">
        <MetricLine label="program" value={input.insight.program ?? "import scope first"} theme={input.theme} />
        <MetricLine label="latest job" value={input.insight.jobs.latest ? `${input.insight.jobs.latest.status} ${input.insight.jobs.latest.type}` : "none"} theme={input.theme} />
        <MetricLine label="signals" value={`${input.insight.recon.inScope} recon, ${input.insight.candidates.total} candidates`} theme={input.theme} />
      </Box>
      <Box flexDirection="column" marginTop={1}>
        <Text>
          <Text color={input.theme.secondary}>$ </Text>bugbounty hunt doctor --json
        </Text>
        <Text>
          <Text color={input.theme.secondary}>$ </Text>bugbounty hunt recon &lt;target&gt; --profile web --dry-run
        </Text>
        <Text>
          <Text color={input.theme.secondary}>$ </Text>bugbounty hunt playbook xss &lt;target&gt; --dry-run
        </Text>
        <Text>
          <Text color={input.theme.secondary}>$ </Text>bugbounty results --min-score 60
        </Text>
      </Box>
      <Box marginTop={1}>
        <Text color={input.theme.muted}>active model: {input.provider ? `${input.provider.id}/${input.model ?? "-"}` : "connect provider first"}</Text>
      </Box>
      <NextSteps steps={input.insight.next} theme={input.theme} />
    </Box>
  );
}

function InitPanel(input: { providers: ProviderSummary[]; insight: TuiWorkspaceInsight; theme: TuiTheme }): React.ReactNode {
  const providerReady = input.providers.some((provider) => provider.status === "configured");
  const programReady = input.insight.program !== undefined;
  const scopeReady = input.insight.scope.in > 0;
  const toolsReady = input.insight.tools.approvedExecutables > 0;
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /init
      </Text>
      <Text color={input.theme.muted}>Guided local setup. Nothing scans or submits from this screen.</Text>
      <Box marginTop={1} flexDirection="column">
        <ChecklistLine ok={programReady} label="workspace program" detail={input.insight.program ?? "import a program.yml"} theme={input.theme} />
        <ChecklistLine ok={scopeReady} label="scope guard" detail={`${input.insight.scope.in} in-scope rule(s)`} theme={input.theme} />
        <ChecklistLine ok={providerReady} label="chat provider" detail={providerReady ? providerDoctorLine(input.providers) : "open /connect"} theme={input.theme} />
        <ChecklistLine
          ok={input.insight.integrations.configured > 0}
          label="integrations"
          detail={`${input.insight.integrations.configured}/${input.insight.integrations.total} configured`}
          theme={input.theme}
        />
        <ChecklistLine
          ok={toolsReady}
          label="tool approval"
          detail={`${input.insight.tools.approvedExecutables} approved executable(s)`}
          theme={input.theme}
        />
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text color={input.theme.secondary}>bootstrap commands</Text>
        <CommandLine command="bugbounty init" theme={input.theme} />
        <CommandLine command="bugbounty import <program.yml>" theme={input.theme} />
        <CommandLine command="bugbounty providers connect openai --api-key-env OPENAI_API_KEY" theme={input.theme} />
        <CommandLine command="bugbounty hunt doctor <target> --profile web" theme={input.theme} />
        <CommandLine command="bugbounty hunt recon <target> --profile web --dry-run" theme={input.theme} />
      </Box>
      <NextSteps steps={input.insight.next} theme={input.theme} />
    </Box>
  );
}

function ToolsPanel(input: { insight: TuiWorkspaceInsight; showDetails: boolean; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /tools
      </Text>
      <Text color={input.theme.muted}>Trusted bounty tool registry, install checks, and executable approvals.</Text>
      <Box marginTop={1} flexDirection="column">
        <MetricLine label="trusted" value={`${input.insight.tools.total} tool(s)`} theme={input.theme} />
        <MetricLine label="available" value={`${input.insight.tools.available} on PATH/package`} theme={input.theme} />
        <MetricLine label="approved" value={`${input.insight.tools.approvedExecutables} executable approval(s)`} theme={input.theme} />
        <MetricLine label="review gate" value={`${input.insight.tools.reviewRequired} review-required, ${input.insight.tools.activeScanning} active-scan`} theme={input.theme} />
        <MetricLine label="missing" value={`${input.insight.tools.missing}`} theme={input.theme} />
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text color={input.theme.secondary}>readiness</Text>
        {input.insight.tools.top.length === 0 ? (
          <Text color={input.theme.warning}>No trusted tools loaded.</Text>
        ) : (
          input.insight.tools.top.map((tool) => (
            <StatusRow
              key={tool.name}
              label={tool.name}
              status={`${tool.status}${tool.approved ? " + approved" : ""}`}
              detail={input.showDetails ? tool.message : tool.category}
              theme={input.theme}
            />
          ))
        )}
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text color={input.theme.secondary}>commands</Text>
        <CommandLine command="bugbounty tools doctor" theme={input.theme} />
        <CommandLine command="bugbounty tools approve-executable <tool> --command <absolute-path>" theme={input.theme} />
        <CommandLine command="bugbounty tools approved-executables" theme={input.theme} />
      </Box>
    </Box>
  );
}

function McpPanel(input: { insight: TuiWorkspaceInsight; showDetails: boolean; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /mcp
      </Text>
      <Text color={input.theme.muted}>MCP and adapter readiness. Execution stays gated by scope, policy, and approvals.</Text>
      <Box marginTop={1} flexDirection="column">
        <MetricLine label="total" value={`${input.insight.integrations.total} adapter(s)`} theme={input.theme} />
        <MetricLine label="configured" value={`${input.insight.integrations.configured}`} theme={input.theme} />
        <MetricLine label="planned" value={`${input.insight.integrations.planned}`} theme={input.theme} />
        <MetricLine label="disabled" value={`${input.insight.integrations.disabled}`} theme={input.theme} />
        <MetricLine label="mcp" value={`${input.insight.integrations.mcp}`} theme={input.theme} />
        <MetricLine label="risky caps" value={`${input.insight.integrations.risky}`} theme={input.theme} />
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text color={input.theme.secondary}>adapters</Text>
        {input.insight.integrations.top.length === 0 ? (
          <Text color={input.theme.warning}>Import a program to inspect integration config.</Text>
        ) : (
          input.insight.integrations.top.map((integration) => (
            <StatusRow
              key={integration.name}
              label={integration.name}
              status={integration.status}
              detail={input.showDetails ? integration.message ?? `${integration.capabilities} capabilities` : integration.type}
              theme={input.theme}
            />
          ))
        )}
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text color={input.theme.secondary}>commands</Text>
        <CommandLine command="bugbounty integrations list" theme={input.theme} />
        <CommandLine command="bugbounty integrations doctor" theme={input.theme} />
        <CommandLine command="bugbounty integrations approve-executable <name> --command <absolute-path>" theme={input.theme} />
      </Box>
    </Box>
  );
}

function HelpPanel(input: { providers: ProviderSummary[]; customCommands: TuiCustomCommand[]; theme: TuiTheme }): React.ReactNode {
  const helpCommands = HELP_COMMAND_IDS
    .map((id) => SLASH_COMMANDS.find((command) => command.id === id))
    .filter((command): command is SlashCommandSpec => command !== undefined);
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        /help
      </Text>
      <Text color={input.theme.muted}>OpenCode-style controls for BountyPilot. Press / for the full command palette.</Text>
      <Box flexDirection="column" marginTop={1}>
        <Text color={input.theme.secondary}>essential commands</Text>
        {helpCommands.map((command) => (
          <Text key={command.id}>
            <Text color={input.theme.secondary}>{command.id.padEnd(10)}</Text>
            <Text>{command.description}</Text>
          </Text>
        ))}
      </Box>
      <Box marginTop={1} flexDirection="column">
        <Text>
          <Text color={input.theme.warning}>Tab</Text> switch Build / Plan / Hunt / Review
        </Text>
        <Text>
          <Text color={input.theme.warning}>Ctrl+P</Text> command palette
        </Text>
        <Text>
          <Text color={input.theme.warning}>@</Text> fuzzy file/context picker
        </Text>
        <Text>
          <Text color={input.theme.warning}>!</Text> plan safe shell/action commands only
        </Text>
        <Text>
          <Text color={input.theme.warning}>Ctrl+T</Text> toggle thinking display
        </Text>
        <Text>
          <Text color={input.theme.warning}>Ctrl+X</Text> leader: n new, h help, l sessions, m models, a mode, i init, d details, c compact, q quit
        </Text>
        <Text color={input.providers.some((provider) => provider.status === "configured") ? input.theme.success : input.theme.warning}>
          {providerDoctorLine(input.providers)}
        </Text>
      </Box>
      {input.customCommands.length > 0 && (
        <Box marginTop={1} flexDirection="column">
          <Text color={input.theme.secondary}>custom commands</Text>
          {input.customCommands.slice(0, 4).map((command) => (
            <Text key={command.id}>
              <Text color={input.theme.secondary}>{command.id.padEnd(14)}</Text>
              <Text color={input.theme.muted}>{customCommandDetail(command)}</Text>
            </Text>
          ))}
          {input.customCommands.length > 4 && <Text color={input.theme.muted}>  {input.customCommands.length - 4} more custom commands in / palette.</Text>}
        </Box>
      )}
    </Box>
  );
}

function Transcript(input: {
  messages: ProviderChatMessage[];
  title?: string;
  metrics?: string;
  contextFiles: string[];
  width: number;
  scrollOffset: number;
  hasOlder: boolean;
  hasNewer: boolean;
  totalMessages: number;
  theme: TuiTheme;
}): React.ReactNode {
  if (input.messages.length === 0) {
    return <WelcomeScreen contextFiles={input.contextFiles} width={input.width} theme={input.theme} />;
  }
  return (
    <Box flexDirection="column" paddingTop={1}>
      {input.title && <SessionTitleBlock title={input.title} metrics={input.metrics} width={input.width} theme={input.theme} />}
      {(input.hasOlder || input.hasNewer) && (
        <Text color={input.theme.muted}>
          {input.hasOlder ? "PageUp/Home older" : "top"}  {input.hasNewer ? "PageDown/End newer" : "newest"}  {input.totalMessages} messages
        </Text>
      )}
      {input.messages.map((message, index) => (
        <TranscriptMessage key={`${message.role}-${index}`} message={message} width={input.width} theme={input.theme} />
      ))}
    </Box>
  );
}

function SessionTitleBlock(input: { title: string; metrics?: string; width: number; theme: TuiTheme }): React.ReactNode {
  const width = boundedContentWidth(input.width);
  const contentWidth = Math.max(12, width - 4);
  const metrics = input.metrics && contentWidth >= 44 ? input.metrics : "";
  const titleWidth = metrics ? Math.max(12, contentWidth - metrics.length - 1) : contentWidth;
  const title = truncateTuiText(`# ${input.title}`, titleWidth);
  const gap = metrics ? " ".repeat(Math.max(1, contentWidth - title.length - metrics.length)) : "";
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text backgroundColor={input.theme.surface}>
        <Text color={input.theme.muted}>│ </Text>
        <Text bold>{title}</Text>
        {metrics ? (
          <Text color={input.theme.muted}>{gap}{metrics}</Text>
        ) : (
          <Text>{padTuiLine("", Math.max(0, contentWidth - title.length))}</Text>
        )}
      </Text>
    </Box>
  );
}

function WelcomeScreen(input: { contextFiles: string[]; width: number; theme: TuiTheme }): React.ReactNode {
  return (
    <Box flexDirection="column" paddingTop={1}>
      {input.contextFiles.length > 0 && (
        <Text color={input.theme.secondary}>context {input.contextFiles.map((file) => `@${file}`).join(" ")}</Text>
      )}
    </Box>
  );
}

function sessionTitleFromMessages(messages: ProviderChatMessage[]): string | undefined {
  const firstUser = messages.find((message) => message.role === "user");
  if (!firstUser) return undefined;
  const normalized = firstUser.content.replace(/\s+/g, " ").trim();
  if (!normalized) return "BountyPilot workflow";
  return truncateTuiText(normalized, 76);
}

function TranscriptMessage(input: { message: ProviderChatMessage; width: number; theme: TuiTheme }): React.ReactNode {
  if (input.message.role === "user") {
    return (
      <MessageBlock
        color={input.theme.mode.chat}
        lines={input.message.content.split(/\r?\n/)}
        width={boundedContentWidth(input.width)}
        theme={input.theme}
      />
    );
  }
  return (
    <AssistantMessage content={input.message.content} width={boundedContentWidth(input.width)} theme={input.theme} />
  );
}

function AssistantMessage(input: { content: string; width: number; theme: TuiTheme }): React.ReactNode {
  const contentWidth = Math.max(16, input.width - 2);
  return (
    <Box flexDirection="column" marginBottom={1}>
      {input.content.split(/\r?\n/).flatMap((line, lineIndex) => {
        const kind = classifyAssistantLine(line);
        const wrapped = wrapTuiText(line || " ", contentWidth);
        return wrapped.map((wrappedLine, wrappedIndex) => (
          <AssistantLine
            key={`${lineIndex}-${wrappedIndex}`}
            line={wrappedLine}
            kind={kind}
            theme={input.theme}
          />
        ));
      })}
    </Box>
  );
}

function AssistantLine(input: { line: string; kind: TuiAssistantLineKind; theme: TuiTheme }): React.ReactNode {
  if (input.kind === "blank") return <Text> </Text>;
  if (input.kind === "error") return <Text color={input.theme.error}>{input.line}</Text>;
  if (input.kind === "command") return <Text color={input.theme.secondary}>{input.line}</Text>;
  if (input.kind === "tool") return <Text color={input.theme.muted}>{input.line}</Text>;
  if (input.kind === "status") return <Text color={input.theme.muted}>{input.line}</Text>;
  return <Text>{input.line}</Text>;
}

function MessageBlock(input: { color: string; lines: string[]; width: number; theme: TuiTheme }): React.ReactNode {
  const contentWidth = Math.max(12, input.width - 4);
  const lines = input.lines.flatMap((line) => wrapTuiText(line || " ", contentWidth));
  return (
    <Box flexDirection="column" marginBottom={1}>
      {lines.map((line, index) => (
        <Text key={index} backgroundColor={input.theme.surface}>
          <Text color={input.color}>│ </Text>
          {padTuiLine(line, contentWidth)}
        </Text>
      ))}
    </Box>
  );
}

function WelcomeCommand(input: { command: string; detail: string; keybind: string; theme: TuiTheme }): React.ReactNode {
  return (
    <Text>
      <Text color={input.theme.secondary}>{input.command.padEnd(11)}</Text>
      <Text>{input.detail.padEnd(20)}</Text>
      <Text color={input.theme.muted}>{input.keybind}</Text>
    </Text>
  );
}

function MetaPanel(input: {
  providers: ProviderSummary[];
  session: TuiSessionRecord;
  mode: TuiMode;
  contextFiles: string[];
  insight: TuiWorkspaceInsight;
  showDetails: boolean;
  showThinking: boolean;
  theme: TuiTheme;
}): React.ReactNode {
  const ready = input.providers.filter((provider) => provider.status === "configured").length;
  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text color={input.theme.accent} bold>
        workspace
      </Text>
      <Text color={input.theme.muted}>session {input.session.id.slice(-13)}</Text>
      <Text color={input.theme.muted}>mode {input.mode}</Text>
      <Text color={input.theme.muted}>details {input.showDetails ? "on" : "off"}</Text>
      <Text color={input.theme.muted}>thinking {input.showThinking ? "visible" : "direct"}</Text>
      <Text color={input.theme.muted}>providers {ready}/{input.providers.length}</Text>
      <Text color={input.theme.muted}>context {input.contextFiles.length}</Text>
      <Text color={input.theme.muted}>program {input.insight.program ?? "none"}</Text>
      <Text color={input.theme.muted}>findings {input.insight.findings.total}</Text>
      <Text color={input.theme.muted}>recon {input.insight.recon.inScope}</Text>
      {input.showDetails && (
        <>
          <Text color={input.theme.muted}>tools {input.insight.tools.available}/{input.insight.tools.total}</Text>
          <Text color={input.theme.muted}>approvals {input.insight.tools.approvedExecutables}</Text>
          <Text color={input.theme.muted}>mcp {input.insight.integrations.configured}/{input.insight.integrations.total}</Text>
        </>
      )}
      <Box marginTop={1} flexDirection="column">
        <Text color={input.theme.accent} bold>
          safety
        </Text>
        <Text color={input.theme.muted}>dry-run first</Text>
        <Text color={input.theme.muted}>scope guard on</Text>
        <Text color={input.theme.muted}>approval gate on</Text>
      </Box>
    </Box>
  );
}

function MetricLine(input: { label: string; value: string | number; theme: TuiTheme }): React.ReactNode {
  return (
    <Text>
      <Text color={input.theme.muted}>{input.label.padEnd(12)}</Text>
      <Text>{String(input.value)}</Text>
    </Text>
  );
}

function ChecklistLine(input: { ok: boolean; label: string; detail: string; theme: TuiTheme }): React.ReactNode {
  return (
    <Text>
      <Text color={input.ok ? input.theme.success : input.theme.warning}>{input.ok ? "[ok] " : "[ ] "}</Text>
      <Text>{input.label.padEnd(18)}</Text>
      <Text color={input.theme.muted}>{input.detail}</Text>
    </Text>
  );
}

function CommandLine(input: { command: string; theme: TuiTheme }): React.ReactNode {
  return (
    <Text>
      <Text color={input.theme.secondary}>$ </Text>
      {input.command}
    </Text>
  );
}

function StatusRow(input: { label: string; status: string; detail: string; theme: TuiTheme }): React.ReactNode {
  return (
    <Text>
      <Text color={statusColor(input.status, input.theme)}>{input.status.padEnd(18)}</Text>
      <Text>{input.label.padEnd(18)}</Text>
      <Text color={input.theme.muted}>{input.detail}</Text>
    </Text>
  );
}

function NextSteps(input: { steps: string[]; theme: TuiTheme }): React.ReactNode {
  return (
    <Box marginTop={1} flexDirection="column">
      <Text color={input.theme.secondary}>next</Text>
      {input.steps.slice(0, 4).map((step) => (
        <Text key={step}>
          <Text color={input.theme.muted}>- </Text>
          {step}
        </Text>
      ))}
    </Box>
  );
}

function InlineCommandHints(input: { commands: SlashCommandSpec[]; theme: TuiTheme }): React.ReactNode {
  return (
    <Box paddingX={1}>
      <Text color={input.theme.muted}>
        {input.commands.map((command) => `${command.id} ${command.title}`).join("   ")}
      </Text>
    </Box>
  );
}

function NoticeBar(input: { notice: Notice; busy: boolean; theme: TuiTheme }): React.ReactNode {
  if (!input.busy && input.notice.text.trim().length === 0) return null;
  const color =
    input.notice.kind === "ok"
      ? input.theme.success
      : input.notice.kind === "warn"
        ? input.theme.warning
        : input.notice.kind === "error"
          ? input.theme.error
          : input.theme.muted;
  return (
    <Box paddingX={2}>
      <Text color={color}>{input.busy ? "* " : "  "}{input.notice.text}</Text>
    </Box>
  );
}

function Composer(input: {
  value: string;
  cursor: number;
  screen: TuiScreen;
  connectStage: ConnectStage;
  mode: TuiMode;
  provider?: ProviderSummary;
  model?: string;
  modelLabelOverride?: string;
  theme: TuiTheme;
}): React.ReactNode {
  const cursor = boundedComposerCursor(input.value, input.cursor);
  const modeLabel = displayAgentName(input.mode);
  const modelText = input.modelLabelOverride ?? (input.provider ? displayModelLabel(input.provider.id, input.model) : "connect provider");
  return (
    <Box flexDirection="column" paddingX={2} marginTop={1}>
      <Box flexDirection="row" backgroundColor={input.theme.surface} paddingY={1}>
        <Text color={input.theme.mode[input.mode]} backgroundColor={input.theme.surface}>│ </Text>
        <Box flexDirection="column" flexGrow={1}>
          <Text backgroundColor={input.theme.surface}>
            <Text>{input.value.slice(0, cursor)}</Text>
            <Text inverse>{input.value[cursor] ?? " "}</Text>
            <Text>{input.value.slice(cursor + 1) || " "}</Text>
          </Text>
          <Text backgroundColor={input.theme.surface}>
            <Text color={input.theme.mode[input.mode]}>{modeLabel}</Text>
            <Text color={input.theme.muted}>  {modelText}  </Text>
            <Text color={input.theme.accent}>BountyPilot</Text>
            <Text color={input.theme.muted}> Zen</Text>
          </Text>
        </Box>
      </Box>
    </Box>
  );
}

function FooterLine(input: {
  mode: TuiMode;
  leaderArmed: boolean;
  theme: TuiTheme;
}): React.ReactNode {
  return (
    <Box paddingX={2} marginBottom={1} justifyContent="space-between">
      <Text>
        <Text color={input.theme.mode[input.mode]}>.........</Text>
        {input.leaderArmed && <Text color={input.theme.warning}>  leader</Text>}
      </Text>
      <Text>
        <Text color={input.theme.muted}>esc interrupt  ctrl+t variants  tab </Text>
        <Text color={input.theme.secondary}>agents</Text>
        <Text color={input.theme.muted}>  ctrl+p commands</Text>
      </Text>
    </Box>
  );
}

function displayAgentName(mode: TuiMode): string {
  if (mode === "chat") return "Build";
  return mode[0]!.toUpperCase() + mode.slice(1);
}

function SelectorRow(input: { selected: boolean; label: string; detail: string; theme: TuiTheme }): React.ReactNode {
  const label = truncateTuiText(input.label, 24).padEnd(24);
  const detail = truncateTuiText(input.detail, 60);
  return (
    <Text>
      <Text color={input.selected ? input.theme.secondary : input.theme.muted}>{input.selected ? "> " : "  "}</Text>
      <Text bold={input.selected}>{label}</Text>
      <Text color={input.theme.muted}>  {detail}</Text>
    </Text>
  );
}

function CommandSelectorRow(input: { selected: boolean; command: SlashCommandSpec; theme: TuiTheme }): React.ReactNode {
  const keybind = truncateTuiText(input.command.keybind ?? "", 10).padEnd(10);
  const command = truncateTuiText(input.command.id, 14).padEnd(14);
  const title = truncateTuiText(input.command.title, 22).padEnd(22);
  const detail = truncateTuiText(input.command.description, 42);
  return (
    <Text>
      <Text color={input.selected ? input.theme.secondary : input.theme.muted}>{input.selected ? "> " : "  "}</Text>
      <Text color={input.theme.muted}>{keybind} </Text>
      <Text bold={input.selected}>{command}</Text>
      <Text>{title}</Text>
      <Text color={input.theme.muted}>{detail}</Text>
    </Text>
  );
}

function filterProviders(providers: ProviderCatalogEntry[], query: string): ProviderCatalogEntry[] {
  const terms = searchTerms(query);
  if (terms.length === 0) return providers;
  return providers.filter((provider) =>
    terms.every((term) =>
      [
        provider.id,
        provider.displayName,
        provider.defaultModel,
        provider.notes,
        ...provider.models,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(term),
    ),
  );
}

function mergeCommandSpecs(builtIns: SlashCommandSpec[], customCommands: TuiCustomCommand[]): SlashCommandSpec[] {
  const builtInIds = new Set(builtIns.map((command) => command.id));
  return [
    ...builtIns,
    ...customCommands
      .filter((command) => !builtInIds.has(command.id))
      .map((command) => ({
        id: command.id,
        title: command.title,
        description: command.description,
      })),
  ];
}

function customCommandDetail(command: TuiCustomCommand): string {
  const tags = [command.model ? `model ${command.model}` : undefined, command.agent ? `agent ${command.agent}` : undefined, command.subtask ? "subtask" : undefined]
    .filter(Boolean)
    .join("  ");
  return tags ? `${command.sourcePath}  ${tags}` : command.sourcePath;
}

function providerModelOptions(providers: ProviderSummary[], query = ""): Array<{ provider: string; model: string; selected: boolean }> {
  const terms = searchTerms(query);
  return providers
    .filter((provider) => provider.status === "configured")
    .flatMap((provider) => provider.models.map((model) => ({ provider: provider.id, model, selected: model === provider.model })))
    .filter((option) =>
      terms.every((term) => `${option.provider} ${option.model}`.toLowerCase().includes(term)),
    );
}

function filterSessionOptions(sessions: TuiSessionSummary[], query: string): TuiSessionSummary[] {
  const terms = searchTerms(query);
  if (terms.length === 0) return sessions;
  return sessions.filter((session) =>
    terms.every((term) =>
      [session.id, session.title, session.mode, session.providerId, session.model, String(session.messages)]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(term),
    ),
  );
}

function searchTerms(query: string): string[] {
  return query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

function wrapTuiText(value: string, width: number): string[] {
  const safeWidth = Math.max(8, Math.floor(width));
  if (value.length <= safeWidth) return [value];
  const lines: string[] = [];
  let rest = value;
  while (rest.length > safeWidth) {
    let splitAt = rest.lastIndexOf(" ", safeWidth);
    if (splitAt < Math.floor(safeWidth * 0.45)) splitAt = safeWidth;
    lines.push(rest.slice(0, splitAt).trimEnd());
    rest = rest.slice(splitAt).trimStart();
  }
  lines.push(rest);
  return lines.length > 0 ? lines : [value];
}

function boundedContentWidth(width: number): number {
  return Math.max(32, Math.min(width - 2, CONTENT_MAX_WIDTH));
}

function padTuiLine(value: string, width: number): string {
  return truncateTuiText(value, width).padEnd(Math.max(0, width));
}

function isTuiMode(value: string): value is TuiMode {
  return value === "chat" || value === "plan" || value === "hunt" || value === "review";
}

function safeContextPrompt(cwd: string, files: string[]): string {
  try {
    return buildContextPrompt(cwd, files);
  } catch (error) {
    return `Context attachment failed: ${errorMessage(error)}`;
  }
}

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${Math.round(value / 102.4) / 10} KB`;
  return `${Math.round(value / (1024 * 102.4)) / 10} MB`;
}

function safeProviderList(manager: ProviderManager): ProviderSummary[] {
  try {
    return manager.list();
  } catch {
    return [];
  }
}

function resolveInitialProvider(
  manager: ProviderManager,
  providers: ProviderSummary[],
  providerId?: string,
): ProviderSummary | undefined {
  if (providerId) {
    try {
      const provider = manager.get(providerId);
      return provider.status === "configured" ? provider : undefined;
    } catch {
      return undefined;
    }
  }
  return providers.find((provider) => provider.status === "configured");
}

function trimMessages(messages: ProviderChatMessage[]): ProviderChatMessage[] {
  const system = messages.find((message) => message.role === "system");
  const rest = messages.filter((message) => message.role !== "system").slice(-24);
  return system ? [system, ...rest] : rest;
}

function promptHistoryFromMessages(messages: ProviderChatMessage[]): string[] {
  return messages
    .filter((message) => message.role === "user")
    .map((message) => message.content.trim())
    .filter(Boolean)
    .slice(-50);
}

function withModeContext(messages: ProviderChatMessage[], mode: TuiMode, showThinking: boolean): ProviderChatMessage[] {
  const context = [
    `Current BountyPilot TUI mode is ${mode}.`,
    "Keep all guidance authorized, scoped, local-first, and non-destructive.",
    showThinking ? "When helpful, include a concise visible rationale and next check list, without revealing hidden chain-of-thought." : "",
  ]
    .filter(Boolean)
    .join(" ");
  const [first, ...rest] = messages;
  if (first?.role === "system") {
    return [{ ...first, content: `${first.content} ${context}` }, ...rest];
  }
  return [{ role: "system", content: context }, ...messages];
}

function providerDoctorLine(providers: ProviderSummary[]): string {
  const ready = providers.filter((provider) => provider.status === "configured").length;
  if (ready === 0) return "No ready provider. Use /connect.";
  return `${ready}/${providers.length} provider(s) ready.`;
}

function writeSessionExport(cwd: string, session: TuiSessionRecord, messages: ProviderChatMessage[]): string {
  const dir = path.join(workspacePaths(cwd).root, "sessions", "exports");
  mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${session.id}.md`);
  const body = [
    `# ${session.title}`,
    "",
    `- session: ${session.id}`,
    `- mode: ${session.mode}`,
    `- provider: ${session.providerId ?? "none"}`,
    `- model: ${session.model ?? "none"}`,
    `- exported: ${new Date().toISOString()}`,
    "",
    ...messages
      .filter((message) => message.role !== "system")
      .flatMap((message) => [`## ${message.role}`, "", redactExportText(message.content), ""]),
  ].join("\n");
  writeFileSync(file, body, "utf8");
  return file;
}

function redactExportText(value: string): string {
  return value
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "sk-***")
    .replace(/\b(OPENAI|OPENROUTER|ANTHROPIC|GEMINI)_API_KEY\s*=\s*\S+/gi, "$1_API_KEY=***");
}

function statusColor(status: string, theme: TuiTheme): string {
  if (/blocked|failed|error|misconfigured/.test(status)) return theme.error;
  if (/missing|not_installed|manual|planned|disabled|not_configured/.test(status)) return theme.warning;
  if (/configured|available|approved|ok|ready/.test(status)) return theme.success;
  return theme.muted;
}

function isCtrlKey(input: string, key: InputKey, letter: string): boolean {
  const normalized = letter.toLowerCase();
  const code = normalized.charCodeAt(0) - 96;
  return (key.ctrl && input.toLowerCase() === normalized) || input === String.fromCharCode(code);
}

function isComposerNewline(input: string, key: InputKey): boolean {
  return (key.return && (key.shift || key.ctrl || key.meta)) || isCtrlKey(input, key, "j");
}

function shortProjectName(cwd: string): string {
  const normalized = cwd.replace(/\\/g, "/");
  const name = normalized.split("/").filter(Boolean).pop() ?? cwd;
  return name.length <= 26 ? name : `${name.slice(0, 23)}...`;
}

function errorMessage(error: unknown): string {
  if (error instanceof BountyPilotError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}
