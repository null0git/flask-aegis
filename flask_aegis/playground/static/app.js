(function () {
  "use strict";

  async function runTest(attackId, fieldName, protected_) {
    const card = document.querySelector(`[data-attack="${attackId}"]`);
    const textarea = card.querySelector("textarea");
    const resultEl = card.querySelector(".result");
    const value = textarea.value;

    const base = protected_ ? `/api/protected/${attackId}` : `/api/vuln/${attackId}`;

    let response, body;
    try {
      if (attackId === "xxe" || attackId === "xml_bomb") {
        // XXE/XML-bomb detection depends on a raw XML body + Content-Type
        // -- see flask_aegis/playground/__init__.py's _run_vulnerable.
        response = await fetch(base, {
          method: "POST",
          headers: { "Content-Type": "application/xml" },
          body: value,
        });
      } else if (attackId === "hpp") {
        // Demonstrate parameter pollution by submitting the same key
        // twice with different values.
        const url = `${base}?value=${encodeURIComponent(value)}&value=${encodeURIComponent(value + "-second")}`;
        response = await fetch(url);
      } else if (attackId === "mass_assignment") {
        // Mass assignment is about the *field name itself* being
        // dangerous -- submit the payload as the key (is_admin=true),
        // not as the value of a fixed 'value' field.
        const url = `${base}?${encodeURIComponent(value)}=true`;
        response = await fetch(url);
      } else {
        const url = `${base}?${encodeURIComponent(fieldName)}=${encodeURIComponent(value)}`;
        response = await fetch(url);
      }
      body = await response.json();
    } catch (err) {
      renderResult(resultEl, "blocked", `Request failed: ${err}`, null);
      return;
    }

    if (response.status === 403 || response.status === 429 || response.status === 428) {
      renderResult(
        resultEl, "blocked",
        `Blocked (HTTP ${response.status}) -- ${body.rule || "no rule id"}`,
        body
      );
      return;
    }

    if (body.sanitized) {
      renderResult(resultEl, "sanitized", "Allowed, but sanitized before use", body);
      return;
    }

    renderResult(resultEl, "allowed", protected_ ? "Allowed through" : "Ran unprotected", body);
  }

  function renderResult(el, kind, statusText, body) {
    el.className = `result show ${kind}`;
    const pre = document.createElement("pre");
    pre.textContent = body ? JSON.stringify(body, null, 2) : "";
    el.innerHTML = "";
    const statusLine = document.createElement("div");
    statusLine.className = "status-line";
    statusLine.innerHTML = `<span class="dot"></span><span>${statusText}</span>`;
    el.appendChild(statusLine);
    el.appendChild(pre);
  }

  document.addEventListener("DOMContentLoaded", () => {
    const cards = Array.from(document.querySelectorAll(".card"));

    cards.forEach((card) => {
      const attackId = card.dataset.attack;
      const fieldName = card.dataset.field;
      const button = card.querySelector("button.run");
      const resetButton = card.querySelector("button.reset");
      const textarea = card.querySelector("textarea.payload");
      const toggle = card.querySelector(".toggle input");

      button.addEventListener("click", () => {
        button.disabled = true;
        runTest(attackId, fieldName, toggle.checked).finally(() => {
          button.disabled = false;
        });
      });

      resetButton.addEventListener("click", () => {
        textarea.value = textarea.dataset.default;
        const resultEl = card.querySelector(".result");
        resultEl.className = "result";
        resultEl.innerHTML = "";
      });
    });

    // Search/filter toolbar -- matches against name, category, and rule id
    // (see the data-search attribute rendered per card in index.html).
    const searchInput = document.getElementById("search");
    const countEl = document.getElementById("visible-count");
    const total = cards.length;

    function applyFilter() {
      const term = searchInput.value.trim().toLowerCase();
      let visible = 0;
      cards.forEach((card) => {
        const matches = !term || card.dataset.search.includes(term);
        card.classList.toggle("hidden", !matches);
        if (matches) visible += 1;
      });
      countEl.textContent = `${visible} of ${total} shown`;
    }

    searchInput.addEventListener("input", applyFilter);
    applyFilter();
  });
})();
