(function installOpenAdaptObserver() {
  "use strict";

  if (globalThis.__openadaptBrowserObserverInstalled) return;
  globalThis.__openadaptBrowserObserverInstalled = true;

  const core = globalThis.OpenAdaptObserverCore;
  if (!core) return;

  let configured = false;
  let identitySalt = null;
  let declaredSecretNames = [];
  let documentSecretTainted = false;
  let navigationEpoch = 0;
  let viewportEpoch = 0;
  let topViewportEpoch = 0;
  let resizeTimer = null;

  function eventTarget(event) {
    try {
      const path = event.composedPath ? event.composedPath() : [];
      if (path.length && path[0]?.nodeType === 1) return path[0];
    } catch {
      // Fall through to the browser-provided target.
    }
    return event.target?.nodeType === 1 ? event.target : null;
  }

  function sensitiveElement(element) {
    return !["none", "ordinary"].includes(core.classifyField(element, declaredSecretNames));
  }

  function noteExistingSensitiveValues() {
    for (const element of document.querySelectorAll("input, textarea, select, [contenteditable='true']")) {
      if (!sensitiveElement(element)) continue;
      const value = element.isContentEditable ? element.textContent : element.value;
      if (typeof value === "string" && value.length > 0) {
        documentSecretTainted = true;
        return;
      }
    }
  }

  function pointFor(event, element) {
    if (Number.isFinite(event.clientX) && Number.isFinite(event.clientY)) {
      return { x: Number(event.clientX), y: Number(event.clientY) };
    }
    const rect = element?.getBoundingClientRect?.();
    if (!rect) return null;
    return {
      x: Number(rect.left + rect.width / 2),
      y: Number(rect.top + rect.height / 2),
    };
  }

  function candidateDiscriminator(event) {
    if (event.type === "pointerdown") return "pointerdown";
    if (event.type === "contextmenu") return "contextmenu";
    if (event.type === "input") return "input";
    return "click";
  }

  function captureCandidate(event) {
    if (!configured || !identitySalt || !Number.isFinite(event.timeStamp)) return;
    const element = eventTarget(event);
    const point = pointFor(event, element);
    if (!element || !point || point.x < 0 || point.y < 0) return;
    if (event.type === "input" && sensitiveElement(element)) {
      documentSecretTainted = true;
    }
    noteExistingSensitiveValues();
    const documentTimeOriginMs = Number(performance.timeOrigin);
    const eventMonotonicMs = Number(event.timeStamp);
    void core.observeElement({
      element,
      x: point.x,
      y: point.y,
      identitySalt,
      declaredSecretNames,
      documentSecretTainted,
      navigationEpoch,
      viewportEpoch,
      association: null,
    }).then((payload) => chrome.runtime.sendMessage({
      type: "OPENADAPT_STRUCTURAL_CANDIDATE",
      candidate: {
        event_discriminator: candidateDiscriminator(event),
        document_time_origin_ms: documentTimeOriginMs,
        event_monotonic_ms: eventMonotonicMs,
        captured_monotonic_ms: Number(performance.now()),
        payload: { ...payload, top_viewport_epoch: topViewportEpoch },
      },
      documentClock: core.documentClock(),
    })).catch(() => {
      // Flow will refuse an observer-backed action when no exact candidate exists.
    });
  }

  for (const type of ["pointerdown", "click", "contextmenu", "input"]) {
    document.addEventListener(type, captureCandidate, { capture: true, passive: true });
  }

  document.addEventListener("change", (event) => {
    if (configured && sensitiveElement(eventTarget(event))) documentSecretTainted = true;
  }, { capture: true, passive: true });

  window.addEventListener("resize", () => {
    if (!configured) return;
    if (resizeTimer !== null) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      resizeTimer = null;
      viewportEpoch += 1;
      chrome.runtime.sendMessage({
        type: "OPENADAPT_VIEWPORT_CHANGED",
        origin: location.origin,
        navigationEpoch,
        viewportEpoch,
        viewport: core.viewport(),
        documentClock: core.documentClock(),
      });
    }, 100);
  }, { passive: true });

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "OPENADAPT_TOP_VIEWPORT_EPOCH") {
      if (
        configured &&
        Number.isInteger(message.topViewportEpoch) &&
        message.topViewportEpoch >= topViewportEpoch
      ) topViewportEpoch = message.topViewportEpoch;
      return false;
    }
    if (message?.type !== "OPENADAPT_CONFIGURE") return false;
    if (
      configured ||
      typeof message.identitySalt !== "string" ||
      !/^[0-9a-f]{64}$/.test(message.identitySalt) ||
      !Array.isArray(message.declaredSecretNames) ||
      !Number.isInteger(message.navigationEpoch) ||
      message.navigationEpoch < 0 ||
      !Number.isInteger(message.topViewportEpoch) ||
      message.topViewportEpoch < 0
    ) {
      chrome.runtime.sendMessage({
        type: "OPENADAPT_OBSERVER_ERROR",
        code: "TARGET_DOCUMENT_CHANGED",
      });
      return false;
    }
    configured = true;
    identitySalt = message.identitySalt;
    declaredSecretNames = message.declaredSecretNames.filter(
      (name) => typeof name === "string" && name.length > 0 && name.length <= 128,
    );
    navigationEpoch = message.navigationEpoch;
    topViewportEpoch = message.topViewportEpoch;
    noteExistingSensitiveValues();
    chrome.runtime.sendMessage({
      type: "OPENADAPT_CONTENT_READY",
      origin: location.origin,
      parentFrameId: null,
      navigationEpoch,
      viewportEpoch,
      viewport: core.viewport(),
      documentClock: core.documentClock(),
    });
    return false;
  });

  function bootstrap() {
    chrome.runtime.sendMessage({
      type: "OPENADAPT_CONTENT_BOOTSTRAP",
      origin: location.origin,
      documentClock: core.documentClock(),
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap, { once: true });
  } else {
    bootstrap();
  }
})();
