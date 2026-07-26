/**
 * Read-only BAIT status widget.
 *
 * The target endpoint must expose only approved aggregate fields. Never place
 * an administrative BAIT bearer token or sensitive endpoint data in a browser.
 */
class BaitStatus extends HTMLElement {
  static get observedAttributes() {
    return ["data-api-url", "data-title"];
  }

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this.controller = null;
  }

  connectedCallback() {
    this.render();
    this.load();
  }

  disconnectedCallback() {
    this.controller?.abort();
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      this.render();
      this.load();
    }
  }

  render() {
    const title = this.dataset.title || "BAIT EDR";
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; max-width: 440px; color-scheme: dark; }
        * { box-sizing: border-box; }
        section {
          padding: 20px;
          border: 1px solid #315c50;
          border-radius: 14px;
          background: linear-gradient(145deg, #102a22, #07110e);
          color: #effff9;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
          box-shadow: 0 18px 48px rgba(0, 0, 0, .2);
        }
        header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
        strong { color: #79f2bd; letter-spacing: .06em; }
        .badge {
          padding: 4px 8px;
          border: 1px solid #315c50;
          border-radius: 999px;
          color: #9ab9ae;
          font: 700 .68rem ui-monospace, monospace;
          text-transform: uppercase;
        }
        p { min-height: 2.7em; margin: 15px 0 0; color: #b6d0c6; font-size: .9rem; line-height: 1.5; }
        .ok { color: #79f2bd; border-color: #174f3b; }
        .error { color: #ff9c7d; border-color: #6a3324; }
      </style>
      <section aria-live="polite" aria-busy="true">
        <header><strong></strong><span class="badge">checking</span></header>
        <p>Loading approved aggregate status…</p>
      </section>`;
    this.shadowRoot.querySelector("strong").textContent = title;
  }

  setState(message, state) {
    const panel = this.shadowRoot.querySelector("section");
    const badge = this.shadowRoot.querySelector(".badge");
    const status = this.shadowRoot.querySelector("p");
    status.textContent = message;
    badge.textContent = state;
    badge.className = `badge ${state === "online" ? "ok" : state === "unavailable" ? "error" : ""}`;
    panel.setAttribute("aria-busy", "false");
  }

  async load() {
    const url = this.dataset.apiUrl;
    if (!url) {
      this.setState("Set data-api-url to a sanitized, read-only status endpoint.", "setup");
      return;
    }

    this.controller?.abort();
    this.controller = new AbortController();
    const timeout = window.setTimeout(() => this.controller.abort(), 5000);

    try {
      const response = await fetch(url, {
        headers: { Accept: "application/json" },
        credentials: "omit",
        cache: "no-store",
        signal: this.controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const service = typeof data.status === "string" ? data.status : "unknown";
      const alerts = Number.isFinite(Number(data.alerts)) ? Number(data.alerts) : 0;
      const mode = typeof data.response_mode === "string" ? data.response_mode : "unknown";
      this.setState(
        `Service ${service}. ${alerts} stored alert${alerts === 1 ? "" : "s"}. Response mode: ${mode}.`,
        "online",
      );
    } catch (error) {
      this.setState("Status is currently unavailable. Administrative access is not affected.", "unavailable");
      console.warn("BAIT status widget request failed:", error);
    } finally {
      window.clearTimeout(timeout);
    }
  }
}

if (!customElements.get("bait-status")) {
  customElements.define("bait-status", BaitStatus);
}
