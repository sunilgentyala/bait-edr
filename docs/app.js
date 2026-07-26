(() => {
  "use strict";

  const year = document.getElementById("year");
  if (year) year.textContent = String(new Date().getFullYear());

  const toggle = document.querySelector(".nav-toggle");
  const navigation = document.getElementById("primary-nav");
  if (toggle && navigation) {
    toggle.addEventListener("click", () => {
      const open = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(open));
      navigation.dataset.open = String(open);
    });
    navigation.addEventListener("click", (event) => {
      if (event.target instanceof HTMLAnchorElement) {
        toggle.setAttribute("aria-expanded", "false");
        navigation.dataset.open = "false";
      }
    });
  }

  const pathParts = window.location.pathname.split("/").filter(Boolean);
  const inferredRepository = pathParts.length > 0 ? pathParts[0] : "bait-edr";
  const inferredOwner = window.location.hostname.endsWith(".github.io")
    ? window.location.hostname.replace(".github.io", "")
    : "sunilgentyala";
  const repositoryUrl = `https://github.com/${inferredOwner}/${inferredRepository}`;

  document.querySelectorAll(".repo-link").forEach((link) => {
    if (link instanceof HTMLAnchorElement && window.location.hostname.endsWith(".github.io")) {
      link.href = repositoryUrl;
    }
  });
})();
