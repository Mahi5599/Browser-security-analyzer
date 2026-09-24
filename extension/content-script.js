// Collects DOM facts for the /analyze-url page_signals field. No page content
// is sent anywhere except these booleans/counts to our own backend.
(function () {
  function isCrossDomain(actionAttr) {
    try {
      const action = new URL(actionAttr, location.href);
      return action.hostname !== location.hostname;
    } catch {
      return false;
    }
  }

  function collectSignals() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const hasPasswordField = passwordFields.length > 0;

    let numExternalFormActions = 0;
    document.querySelectorAll("form").forEach((form) => {
      const action = form.getAttribute("action");
      if (action && isCrossDomain(action)) numExternalFormActions += 1;
    });

    const numHiddenIframes = Array.from(document.querySelectorAll("iframe")).filter((f) => {
      const style = window.getComputedStyle(f);
      return style.display === "none" || style.visibility === "hidden" || f.width === "0" || f.height === "0";
    }).length;

    return {
      has_login_form: hasPasswordField,
      has_password_field: hasPasswordField,
      password_field_insecure: hasPasswordField && location.protocol !== "https:",
      form_action_cross_domain: numExternalFormActions > 0,
      num_external_form_actions: numExternalFormActions,
      num_hidden_iframes: numHiddenIframes,
      num_password_fields: passwordFields.length,
    };
  }

  function reportSignals() {
    chrome.runtime.sendMessage({ type: "PAGE_SIGNALS", signals: collectSignals() });
  }

  reportSignals();
  // Some login forms render late (SPAs); check once more after the page settles.
  setTimeout(reportSignals, 1500);
})();
