// Caddy WAF UI client behavior (CSP script-src 'self'): no inline handlers.
// All handlers are attached here and wired via data-* attributes.
(function () {
  // Dismiss flash notices (data-dismiss-toast on the close control).
  document.querySelectorAll("[data-dismiss-toast]").forEach(function (el) {
    el.addEventListener("click", function () {
      el.parentElement.style.display = "none";
    });
  });

  // Confirmación al pasar el WAF a modo Off (bypass de protección): el
  // mensaje viaja server-side en data-confirm-off. En sites.html el form
  // usa radios; en overview.html botones submit name=mode. El confirm solo
  // se dispara cuando el modo elegido es Off.
  document.querySelectorAll("form[data-confirm-off]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var mode;
      var radio = form.querySelector('input[type="radio"][name="mode"]:checked');
      if (radio) {
        mode = radio.value;
      } else if (event.submitter && event.submitter.getAttribute("name") === "mode") {
        mode = event.submitter.getAttribute("value");
      }
      if (mode === "Off" && !window.confirm(form.getAttribute("data-confirm-off"))) {
        event.preventDefault();
      }
    });
  });

  // Confirmation dialog for destructive actions (snapshot restore). The
  // message is rendered server-side into data-confirm.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });
})();
