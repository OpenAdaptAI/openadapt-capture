import {
  COMMAND_SCHEMA,
  CONTROL_SCHEMA,
  DeliveryQueue,
  EXTENSION_ID,
  MAX_BUFFERED_BYTES,
  MAX_CANDIDATE_AGE_MS,
  MAX_UNACKNOWLEDGED_MESSAGES,
  NATIVE_HOST,
  PROTOCOL_SCHEMA,
  makeEnvelope,
  normalizeOrigin,
  sha256Hex,
  validAcknowledgement,
  validObservationCommand,
  validSessionAbort,
  validSessionOffer,
} from "./protocol.js";

const SESSION_STORAGE_KEY = "openadaptBrowserObserverSessionV1";
const INSTALLATION_STORAGE_KEY = "openadaptBrowserObserverInstallationV1";
const HEARTBEAT_ALARM = "openadapt-browser-observer-heartbeat";

let port = null;
let offer = null;
let delivery = new DeliveryQueue();
let installationIdSha256 = null;
let releaseIdentity = null;
let failedCode = null;
let lastServerSequence = 0;
let restoredSessionId = null;
const boundTabs = new Map();
const frameDocuments = new Map();
const tabNavigationEpochs = new Map();
const documentBindings = new Map();
const documentViewportHistory = new Map();
let candidates = [];
let candidateBytes = 0;

const RELEASE_MEMBERS = new Set([
  "LICENSE",
  "README.md",
  "background.js",
  "content.js",
  "icons/icon16.png",
  "icons/icon48.png",
  "icons/icon128.png",
  "manifest.json",
  "observer_core.js",
  "protocol.js",
]);

async function sha256Bytes(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function loadReleaseIdentity() {
  const response = await fetch(chrome.runtime.getURL("browser-observer.inventory.json"), { cache: "no-store" });
  if (!response.ok) throw new Error("release inventory is unavailable");
  const raw = await response.arrayBuffer();
  const inventorySha256 = await sha256Bytes(raw);
  const inventory = JSON.parse(new TextDecoder().decode(raw));
  if (
    inventory?.schema !== "openadapt.capture.browser-observer-inventory/v1" ||
    inventory.extension_id !== chrome.runtime.id ||
    inventory.extension_version !== chrome.runtime.getManifest().version ||
    inventory.capture_version !== chrome.runtime.getManifest().version ||
    inventory.direct_replay !== false ||
    !/^[0-9a-f]{40}$/.test(inventory.source_commit) ||
    !Array.isArray(inventory.members) ||
    inventory.members.length !== RELEASE_MEMBERS.size
  ) throw new Error("release inventory identity differs");
  const memberNames = new Set(inventory.members.map((member) => member?.path));
  if (memberNames.size !== RELEASE_MEMBERS.size || [...RELEASE_MEMBERS].some((name) => !memberNames.has(name))) {
    throw new Error("release inventory members differ");
  }
  for (const member of inventory.members) {
    if (!/^[0-9a-f]{64}$/.test(member?.sha256) || !Number.isInteger(member?.size_bytes)) {
      throw new Error("release inventory member contract differs");
    }
    const memberResponse = await fetch(chrome.runtime.getURL(member.path), { cache: "no-store" });
    if (!memberResponse.ok) throw new Error("release member is unavailable");
    const content = await memberResponse.arrayBuffer();
    if (content.byteLength !== member.size_bytes || await sha256Bytes(content) !== member.sha256) {
      throw new Error("release member digest differs");
    }
  }
  releaseIdentity = {
    sourceCommit: inventory.source_commit,
    inventorySha256,
  };
}

function serializedSize(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function pruneCandidates(nowMs = Date.now()) {
  candidates = candidates.filter((candidate) => (
    Number.isFinite(candidate.received_at_ms) &&
    nowMs - candidate.received_at_ms <= MAX_CANDIDATE_AGE_MS
  ));
  candidateBytes = candidates.reduce((total, candidate) => total + serializedSize(candidate), 0);
}

function storeCandidate(candidate) {
  pruneCandidates();
  const previous = candidates[candidates.length - 1];
  if (
    candidate.event_discriminator === "input" &&
    previous?.event_discriminator === "input" &&
    previous.tab_id === candidate.tab_id &&
    previous.document_id === candidate.document_id &&
    previous.frame_id === candidate.frame_id &&
    JSON.stringify(previous.payload?.target) === JSON.stringify(candidate.payload?.target)
  ) return false;
  const size = serializedSize(candidate);
  if (
    candidates.length + 1 > MAX_UNACKNOWLEDGED_MESSAGES ||
    candidateBytes + size > MAX_BUFFERED_BYTES
  ) throw new Error("BACKPRESSURE_LIMIT");
  candidates.push(candidate);
  candidateBytes += size;
  return true;
}

function bindDocument(documentId, binding) {
  if (!documentBindings.has(documentId) && documentBindings.size >= 512) {
    throw new Error("BACKPRESSURE_LIMIT");
  }
  documentBindings.set(documentId, binding);
}

async function loadInstallationIdentity() {
  const stored = await chrome.storage.local.get(INSTALLATION_STORAGE_KEY);
  let seed = stored[INSTALLATION_STORAGE_KEY];
  if (typeof seed !== "string" || !/^[0-9a-f]{64}$/.test(seed)) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    seed = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    await chrome.storage.local.set({ [INSTALLATION_STORAGE_KEY]: seed });
  }
  installationIdSha256 = await sha256Hex(`openadapt-browser-observer-installation-v1\n${seed}`);
}

async function restoreSessionState() {
  const stored = await chrome.storage.session.get(SESSION_STORAGE_KEY);
  const state = stored[SESSION_STORAGE_KEY];
  if (!state || typeof state !== "object") return;
  try {
    delivery.restore(state.delivery);
    failedCode = typeof state.failedCode === "string" ? state.failedCode : null;
    lastServerSequence = Number.isInteger(state.lastServerSequence) && state.lastServerSequence >= 0
      ? state.lastServerSequence
      : 0;
    restoredSessionId = typeof state.sessionId === "string" ? state.sessionId : null;
    for (const binding of state.bindings || []) {
      if (binding && Number.isInteger(binding.tabId)) boundTabs.set(binding.tabId, binding);
    }
    for (const entry of state.frameDocuments || []) {
      if (Array.isArray(entry) && entry.length === 2 && typeof entry[0] === "string" && typeof entry[1] === "string") {
        frameDocuments.set(entry[0], entry[1]);
      }
    }
    for (const entry of state.navigationEpochs || []) {
      if (Array.isArray(entry) && Number.isInteger(entry[0]) && Number.isInteger(entry[1])) {
        tabNavigationEpochs.set(entry[0], entry[1]);
      }
    }
    for (const entry of state.documentBindings || []) {
      if (Array.isArray(entry) && entry.length === 2 && typeof entry[0] === "string") {
        documentBindings.set(entry[0], entry[1]);
      }
    }
    for (const entry of state.viewportHistory || []) {
      if (Array.isArray(entry) && typeof entry[0] === "string" && Array.isArray(entry[1])) {
        documentViewportHistory.set(entry[0], entry[1]);
      }
    }
    if (documentBindings.size > 512) throw new Error("stored document bindings exceed the admitted bound");
    candidates = Array.isArray(state.candidates) ? state.candidates : [];
    pruneCandidates();
    if (
      candidates.length > MAX_UNACKNOWLEDGED_MESSAGES ||
      candidateBytes > MAX_BUFFERED_BYTES
    ) throw new Error("stored observer candidates exceed the admitted bound");
  } catch {
    failedCode = "BACKPRESSURE_LIMIT";
    delivery = new DeliveryQueue();
    boundTabs.clear();
  }
}

async function persistSessionState() {
  await chrome.storage.session.set({
    [SESSION_STORAGE_KEY]: {
      delivery: delivery.snapshot(),
      failedCode,
      lastServerSequence,
      sessionId: offer?.session_id || restoredSessionId,
      bindings: [...boundTabs.values()],
      frameDocuments: [...frameDocuments.entries()],
      navigationEpochs: [...tabNavigationEpochs.entries()],
      documentBindings: [...documentBindings.entries()],
      viewportHistory: [...documentViewportHistory.entries()],
      candidates,
    },
  });
}

function updateBadge() {
  if (failedCode) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#B42318" });
  } else if (offer && port) {
    chrome.action.setBadgeText({ text: boundTabs.size ? "ON" : "+" });
    chrome.action.setBadgeBackgroundColor({ color: "#176B45" });
  } else {
    chrome.action.setBadgeText({ text: "…" });
    chrome.action.setBadgeBackgroundColor({ color: "#667085" });
  }
}

async function failClosed(code) {
  if (failedCode) return;
  if (offer && port) {
    try {
      const envelope = makeEnvelope({
        sessionId: offer.session_id,
        sequence: delivery.nextSequence(),
        kind: "error",
        payload: { code },
      });
      delivery.enqueue(envelope);
      port.postMessage(envelope);
    } catch {
      // The bridge detects a missing heartbeat or sequence if the queue is full.
    }
  }
  failedCode = code;
  updateBadge();
  await persistSessionState();
}

function transmitPending(afterSequence = delivery.lastAcknowledged) {
  if (!port) return;
  for (const envelope of delivery.pendingAfter(afterSequence)) port.postMessage(envelope);
}

async function enqueue(kind, payload, documentClock = null) {
  if (!offer || failedCode) throw new Error("observer session is unavailable");
  const envelope = makeEnvelope({
    sessionId: offer.session_id,
    sequence: delivery.nextSequence(),
    kind,
    payload,
    documentClock,
  });
  try {
    delivery.enqueue(envelope);
  } catch (error) {
    await failClosed("BACKPRESSURE_LIMIT");
    throw error;
  }
  await persistSessionState();
  if (port) port.postMessage(envelope);
  return envelope.sequence;
}

async function handleOffer(message) {
  if (!validSessionOffer(message) || chrome.runtime.id !== EXTENSION_ID || !releaseIdentity) {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  const previousSessionId = offer?.session_id || restoredSessionId;
  if (previousSessionId && previousSessionId !== message.session_id) {
    delivery = new DeliveryQueue();
    boundTabs.clear();
    frameDocuments.clear();
    tabNavigationEpochs.clear();
    documentBindings.clear();
    documentViewportHistory.clear();
    candidates = [];
    candidateBytes = 0;
    failedCode = null;
    lastServerSequence = 0;
  }
  offer = message;
  restoredSessionId = message.session_id;
  if (message.resume_after_server_sequence !== lastServerSequence) {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  if (delivery.lastAcknowledged > message.resume_after_sequence) {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  if (message.resume_after_sequence > delivery.lastAcknowledged) {
    delivery.acknowledge(message.resume_after_sequence);
  }
  const helloAlreadyPending = delivery.items.some((item) => {
    try { return JSON.parse(item.serialized).kind === "session_hello"; } catch { return false; }
  });
  if (delivery.lastAcknowledged === 0 && !helloAlreadyPending) {
    await enqueue("session_hello", {
      extension_id: chrome.runtime.id,
      installation_id_sha256: installationIdSha256,
      extension_version: chrome.runtime.getManifest().version,
      extension_source_commit: releaseIdentity.sourceCommit,
      extension_inventory_sha256: releaseIdentity.inventorySha256,
      protocol_schema: PROTOCOL_SCHEMA,
    });
  }
  transmitPending(message.resume_after_sequence);
  updateBadge();
}

async function handleControl(message) {
  if (!message || message.schema !== CONTROL_SCHEMA || typeof message.kind !== "string") {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  if (message.kind === "session_offer") {
    await handleOffer(message);
    return;
  }
  if (!offer || message.session_id !== offer.session_id) {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  if (message.kind === "ack") {
    if (!validAcknowledgement(message, offer.session_id)) {
      await failClosed("INVALID_SERVER_COMMAND");
      return;
    }
    try {
      delivery.acknowledge(message.acknowledged_sequence);
      await persistSessionState();
    } catch {
      await failClosed("INVALID_SERVER_COMMAND");
    }
    return;
  }
  if (message.kind === "session_abort") {
    if (!validSessionAbort(message, offer.session_id)) {
      await failClosed("INVALID_SERVER_COMMAND");
      return;
    }
    failedCode = message.code;
    updateBadge();
    await persistSessionState();
  }
}

async function handleObserveCommand(message) {
  if (!offer || failedCode || !validObservationCommand(message, offer.session_id, lastServerSequence + 1)) {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  if (message.session_id !== offer.session_id) {
    await failClosed("INVALID_SERVER_COMMAND");
    return;
  }
  lastServerSequence = message.server_sequence;
  pruneCandidates();
  const matches = candidates.filter((candidate) => (
    candidate.tab_id === message.tab_id &&
    candidate.top_document_id === message.top_document_id &&
    candidate.navigation_epoch === message.navigation_epoch &&
    candidate.top_viewport_epoch === message.top_viewport_epoch &&
    candidate.event_discriminator === message.event_discriminator &&
    candidate.document_time_origin_ms === message.document_time_origin_ms &&
    candidate.event_monotonic_ms === message.event_monotonic_ms &&
    Math.abs(candidate.event_top_x - message.top_x) <= 1 &&
    Math.abs(candidate.event_top_y - message.top_y) <= 1
  ));
  if (matches.length !== 1) {
    await failClosed(matches.length ? "TARGET_DOCUMENT_CHANGED" : "TARGET_NOT_FOUND");
    return;
  }
  const candidate = matches[0];
  const candidateIndex = candidates.indexOf(candidate);
  candidates.splice(candidateIndex, 1);
  candidateBytes -= serializedSize(candidate);
  await persistSessionState();
  const payload = {
    ...candidate.payload,
    tab_id: candidate.tab_id,
    frame_id: candidate.frame_id,
    document_id: candidate.document_id,
    top_document_id: candidate.top_document_id,
    navigation_epoch: candidate.navigation_epoch,
    viewport_epoch: candidate.viewport_epoch,
    top_viewport_epoch: candidate.top_viewport_epoch,
    association: {
      request_id: message.request_id,
      action_id: message.action_id,
      capture_action_sequence: message.capture_action_sequence,
      flow_frame_token_sha256: message.flow_frame_token_sha256,
      event_discriminator: message.event_discriminator,
      document_time_origin_ms: message.document_time_origin_ms,
      event_monotonic_ms: message.event_monotonic_ms,
      top_x: message.top_x,
      top_y: message.top_y,
    },
  };
  delete payload.event_top_x;
  delete payload.event_top_y;
  await enqueue("observation", payload, candidate.document_clock);
}

function connectNativeHost() {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
  } catch {
    port = null;
    updateBadge();
    return;
  }
  port.onMessage.addListener((message) => {
    if (message?.schema === COMMAND_SCHEMA) void handleObserveCommand(message);
    else void handleControl(message);
  });
  port.onDisconnect.addListener(() => {
    port = null;
    updateBadge();
    if (!failedCode) setTimeout(connectNativeHost, 500);
  });
  updateBadge();
}

async function injectObserver(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId, allFrames: true },
    files: ["observer_core.js", "content.js"],
  });
}

chrome.action.onClicked.addListener(async (tab) => {
  if (!offer || failedCode || !Number.isInteger(tab.id) || !Number.isInteger(tab.windowId) || !tab.url) return;
  let origin;
  try { origin = normalizeOrigin(new URL(tab.url).origin); } catch { return; }
  if (!offer.allowed_origins.includes(origin)) {
    await failClosed("ORIGIN_PERMISSION_DENIED");
    return;
  }
  const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
  if (!granted) {
    await failClosed("ORIGIN_PERMISSION_DENIED");
    return;
  }
  const existing = boundTabs.get(tab.id);
  let navigationEpoch = tabNavigationEpochs.get(tab.id) || 0;
  if (existing && existing.origin && existing.origin !== origin) {
    navigationEpoch += 1;
    tabNavigationEpochs.set(tab.id, navigationEpoch);
  }
  boundTabs.set(tab.id, {
    tabId: tab.id,
    windowId: tab.windowId,
    origin,
    openerTabId: existing?.openerTabId ?? (
      Number.isInteger(tab.openerTabId) && boundTabs.has(tab.openerTabId)
      ? tab.openerTabId
      : null
    ),
    topDocumentId: null,
    navigationEpoch,
    viewportEpoch: 0,
  });
  await persistSessionState();
  try { await injectObserver(tab.id); } catch { await failClosed("CONTENT_SCRIPT_UNAVAILABLE"); }
  updateBadge();
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!offer || failedCode || !Number.isInteger(sender.tab?.id) || !boundTabs.has(sender.tab.id)) return false;
  const tabId = sender.tab.id;
  const frameId = Number.isInteger(sender.frameId) ? sender.frameId : 0;
  const documentId = sender.documentId;
  if (typeof documentId !== "string") {
    void failClosed("TARGET_DOCUMENT_CHANGED");
    return false;
  }
  const topBinding = boundTabs.get(tabId);
  const key = `${tabId}:${frameId}`;
  frameDocuments.set(key, documentId);

  if (message?.type === "OPENADAPT_CONTENT_BOOTSTRAP") {
    if (!offer.allowed_origins.includes(message.origin)) {
      void failClosed("ORIGIN_PERMISSION_DENIED");
      return false;
    }
    const topDocumentId = frameId === 0
      ? documentId
      : topBinding.topDocumentId;
    if (typeof topDocumentId !== "string") {
      void failClosed("TARGET_DOCUMENT_CHANGED");
      return false;
    }
    if (frameId === 0) topBinding.topDocumentId = documentId;
    try {
      bindDocument(documentId, {
        tabId,
        topDocumentId,
        origin: message.origin,
        navigationEpoch: tabNavigationEpochs.get(tabId) || 0,
      });
    } catch {
      void failClosed("BACKPRESSURE_LIMIT");
      return false;
    }
    void chrome.tabs.sendMessage(
      tabId,
      {
        type: "OPENADAPT_CONFIGURE",
        identitySalt: offer.identity_salt,
        declaredSecretNames: offer.secret_field_names,
        navigationEpoch: tabNavigationEpochs.get(tabId) || 0,
        topViewportEpoch: topBinding.viewportEpoch || 0,
      },
      { frameId, documentId },
    ).catch(() => failClosed("CONTENT_SCRIPT_UNAVAILABLE"));
    return false;
  }

  if (message?.type === "OPENADAPT_CONTENT_READY") {
    const origin = message.origin;
    if (!offer.allowed_origins.includes(origin)) {
      void failClosed("ORIGIN_PERMISSION_DENIED");
      return false;
    }
    if (frameId === 0) {
      topBinding.topDocumentId = documentId;
      topBinding.origin = origin;
      topBinding.navigationEpoch = tabNavigationEpochs.get(tabId) || 0;
      topBinding.viewportEpoch = message.viewportEpoch;
      const history = documentViewportHistory.get(documentId) || [];
      history.push({ epoch: message.viewportEpoch, viewport: message.viewport });
      documentViewportHistory.set(documentId, history.slice(-32));
      void chrome.tabs.sendMessage(
        tabId,
        {
          type: "OPENADAPT_TOP_VIEWPORT_EPOCH",
          topViewportEpoch: message.viewportEpoch,
        },
      ).catch(() => failClosed("CONTENT_SCRIPT_UNAVAILABLE"));
      void enqueue("target_bind", {
        tab_id: tabId,
        window_id: sender.tab.windowId,
        top_document_id: documentId,
        origin,
        opener_tab_id: topBinding.openerTabId,
        permission_grant: "optional-origin",
        navigation_epoch: topBinding.navigationEpoch,
        viewport_epoch: topBinding.viewportEpoch,
      });
    }
    void enqueue("lifecycle", {
      event: frameId === 0 ? "document_ready" : "frame_attached",
      tab_id: tabId,
      window_id: sender.tab.windowId,
      frame_id: frameId,
      parent_frame_id: Number.isInteger(message.parentFrameId) ? message.parentFrameId : null,
      document_id: documentId,
      top_document_id: topBinding.topDocumentId || documentId,
      origin,
      navigation_epoch: tabNavigationEpochs.get(tabId) || 0,
      viewport_epoch: message.viewportEpoch,
      viewport: message.viewport,
    }, message.documentClock);
    return false;
  }

  if (message?.type === "OPENADAPT_VIEWPORT_CHANGED") {
    if (frameId === 0) {
      topBinding.viewportEpoch = message.viewportEpoch;
      const history = documentViewportHistory.get(topBinding.topDocumentId) || [];
      history.push({ epoch: message.viewportEpoch, viewport: message.viewport });
      documentViewportHistory.set(topBinding.topDocumentId, history.slice(-32));
      void chrome.tabs.sendMessage(
        tabId,
        {
          type: "OPENADAPT_TOP_VIEWPORT_EPOCH",
          topViewportEpoch: message.viewportEpoch,
        },
      ).catch(() => failClosed("CONTENT_SCRIPT_UNAVAILABLE"));
    }
    void enqueue("lifecycle", {
      event: "viewport_changed",
      tab_id: tabId,
      window_id: sender.tab.windowId,
      frame_id: frameId,
      parent_frame_id: null,
      document_id: documentId,
      top_document_id: topBinding.topDocumentId || documentId,
      origin: message.origin,
      navigation_epoch: tabNavigationEpochs.get(tabId) || 0,
      viewport_epoch: message.viewportEpoch,
      viewport: message.viewport,
    }, message.documentClock);
    return false;
  }

  if (message?.type === "OPENADAPT_STRUCTURAL_CANDIDATE") {
    const candidate = message.candidate;
    const documentBinding = documentBindings.get(documentId);
    const viewportMatches = (
      documentViewportHistory.get(documentBinding?.topDocumentId) || []
    ).filter((entry) => (
      entry?.epoch === candidate?.payload?.top_viewport_epoch &&
      entry?.viewport?.width === candidate?.payload?.top_viewport?.width &&
      entry?.viewport?.height === candidate?.payload?.top_viewport?.height &&
      entry?.viewport?.device_scale_factor === candidate?.payload?.top_viewport?.device_scale_factor
    ));
    if (
      !candidate || typeof candidate !== "object" ||
      !["click", "contextmenu", "input", "pointerdown"].includes(candidate.event_discriminator) ||
      !Number.isFinite(candidate.document_time_origin_ms) ||
      !Number.isFinite(candidate.event_monotonic_ms) ||
      !Number.isFinite(candidate.captured_monotonic_ms) ||
      !candidate.payload || typeof candidate.payload !== "object" ||
      !documentBinding || documentBinding.tabId !== tabId ||
      candidate.payload.origin !== documentBinding.origin ||
      candidate.payload.viewport_epoch < 0 ||
      !Number.isInteger(candidate.payload.top_viewport_epoch) ||
      viewportMatches.length !== 1 ||
      !Number.isFinite(candidate.payload.event_top_x) ||
      !Number.isFinite(candidate.payload.event_top_y)
    ) {
      void failClosed("TARGET_DOCUMENT_CHANGED");
      return false;
    }
    try {
      storeCandidate({
        ...candidate,
        payload: candidate.payload,
        tab_id: tabId,
        frame_id: frameId,
        document_id: documentId,
        top_document_id: documentBinding.topDocumentId,
        navigation_epoch: documentBinding.navigationEpoch,
        viewport_epoch: candidate.payload.viewport_epoch,
        top_viewport_epoch: candidate.payload.top_viewport_epoch,
        event_top_x: candidate.payload.event_top_x,
        event_top_y: candidate.payload.event_top_y,
        document_clock: message.documentClock,
        received_at_ms: Date.now(),
      });
      void persistSessionState();
    } catch {
      void failClosed("BACKPRESSURE_LIMIT");
    }
    return false;
  }

  if (message?.type === "OPENADAPT_OBSERVER_ERROR") {
    const allowed = new Set(["CONTENT_SCRIPT_UNAVAILABLE", "TARGET_DOCUMENT_CHANGED", "TARGET_NOT_FOUND"]);
    void failClosed(allowed.has(message.code) ? message.code : "CONTENT_SCRIPT_UNAVAILABLE");
  }
  return false;
});

chrome.webNavigation.onCommitted.addListener((details) => {
  const binding = boundTabs.get(details.tabId);
  if (!binding || !offer || failedCode) return;
  let origin;
  try { origin = normalizeOrigin(new URL(details.url).origin); } catch { return; }
  if (!offer.allowed_origins.includes(origin) || typeof details.documentId !== "string") {
    void failClosed("ORIGIN_PERMISSION_DENIED");
    return;
  }
  if (details.frameId === 0) {
    tabNavigationEpochs.set(details.tabId, (tabNavigationEpochs.get(details.tabId) || 0) + 1);
    binding.origin = origin;
    binding.topDocumentId = details.documentId;
    binding.navigationEpoch = tabNavigationEpochs.get(details.tabId);
    binding.viewportEpoch = 0;
    for (const key of frameDocuments.keys()) {
      if (key.startsWith(`${details.tabId}:`)) frameDocuments.delete(key);
    }
  }
  frameDocuments.set(`${details.tabId}:${details.frameId}`, details.documentId);
  try {
    bindDocument(details.documentId, {
      tabId: details.tabId,
      topDocumentId: binding.topDocumentId,
      origin,
      navigationEpoch: tabNavigationEpochs.get(details.tabId) || 0,
    });
  } catch {
    void failClosed("BACKPRESSURE_LIMIT");
    return;
  }
  const now = Date.now();
  void enqueue("lifecycle", {
    event: "document_committed",
    tab_id: details.tabId,
    window_id: binding.windowId,
    frame_id: details.frameId,
    parent_frame_id: details.parentFrameId >= 0 ? details.parentFrameId : null,
    document_id: details.documentId,
    top_document_id: binding.topDocumentId,
    origin,
    navigation_epoch: tabNavigationEpochs.get(details.tabId) || 0,
    viewport_epoch: 0,
    viewport: null,
  }, { timeOriginMs: now, monotonicMs: 0 });
});

chrome.webNavigation.onDOMContentLoaded.addListener((details) => {
  if (details.frameId !== 0 || !boundTabs.has(details.tabId) || failedCode) return;
  const binding = boundTabs.get(details.tabId);
  void chrome.permissions.contains({ origins: [`${binding.origin}/*`] }).then((granted) => {
    if (granted) return injectObserver(details.tabId);
    updateBadge();
    return undefined;
  }).catch(() => failClosed("CONTENT_SCRIPT_UNAVAILABLE"));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  const binding = boundTabs.get(tabId);
  if (!binding || !binding.topDocumentId || !offer || failedCode) return;
  boundTabs.delete(tabId);
  for (const key of frameDocuments.keys()) if (key.startsWith(`${tabId}:`)) frameDocuments.delete(key);
  for (const [documentId, documentBinding] of documentBindings.entries()) {
    if (documentBinding?.tabId !== tabId) continue;
    documentBindings.delete(documentId);
    documentViewportHistory.delete(documentId);
  }
  const now = Date.now();
  void enqueue("lifecycle", {
    event: "tab_closed",
    tab_id: tabId,
    window_id: binding.windowId,
    frame_id: 0,
    parent_frame_id: null,
    document_id: binding.topDocumentId,
    top_document_id: binding.topDocumentId,
    origin: binding.origin,
    navigation_epoch: binding.navigationEpoch || 0,
    viewport_epoch: binding.viewportEpoch || 0,
    viewport: null,
  }, { timeOriginMs: now, monotonicMs: 0 });
});

chrome.tabs.onActivated.addListener(({ tabId, windowId }) => {
  const binding = boundTabs.get(tabId);
  if (!binding || !binding.topDocumentId || !offer || failedCode) return;
  const now = Date.now();
  void enqueue("lifecycle", {
    event: "tab_activated",
    tab_id: tabId,
    window_id: windowId,
    frame_id: 0,
    parent_frame_id: null,
    document_id: binding.topDocumentId,
    top_document_id: binding.topDocumentId,
    origin: binding.origin,
    navigation_epoch: binding.navigationEpoch || 0,
    viewport_epoch: binding.viewportEpoch || 0,
    viewport: null,
  }, { timeOriginMs: now, monotonicMs: 0 });
});

chrome.windows.onFocusChanged.addListener((windowId) => {
  if (!Number.isInteger(windowId) || windowId < 0 || !offer || failedCode) return;
  const now = Date.now();
  for (const binding of boundTabs.values()) {
    if (binding.windowId !== windowId || !binding.topDocumentId) continue;
    void enqueue("lifecycle", {
      event: "window_focus_changed",
      tab_id: binding.tabId,
      window_id: windowId,
      frame_id: 0,
      parent_frame_id: null,
      document_id: binding.topDocumentId,
      top_document_id: binding.topDocumentId,
      origin: binding.origin,
      navigation_epoch: binding.navigationEpoch || 0,
      viewport_epoch: binding.viewportEpoch || 0,
      viewport: null,
    }, { timeOriginMs: now, monotonicMs: 0 });
  }
});

chrome.tabs.onCreated.addListener((tab) => {
  if (!offer || failedCode || !Number.isInteger(tab.id) || !Number.isInteger(tab.windowId)) return;
  if (!Number.isInteger(tab.openerTabId) || !boundTabs.has(tab.openerTabId)) return;
  boundTabs.set(tab.id, {
    tabId: tab.id,
    windowId: tab.windowId,
    origin: null,
    openerTabId: tab.openerTabId,
    topDocumentId: null,
    navigationEpoch: 0,
    viewportEpoch: 0,
  });
  void persistSessionState();
  updateBadge();
});

chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== HEARTBEAT_ALARM) return;
  if (!port) connectNativeHost();
  if (offer && !failedCode) void enqueue("heartbeat", { last_server_sequence: lastServerSequence });
});

await loadInstallationIdentity();
let releaseIdentityInvalid = false;
try {
  await loadReleaseIdentity();
} catch {
  releaseIdentityInvalid = true;
}
await restoreSessionState();
if (releaseIdentityInvalid) failedCode = "INVALID_SERVER_COMMAND";
if (releaseIdentity) connectNativeHost();
updateBadge();
