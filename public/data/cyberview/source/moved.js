// this page moved to vulnerabilities.html: send visitors (and old bookmarks) there, keeping the query and the #section or #CVE-id.
(function () {
  "use strict";
  try { location.replace("vulnerabilities.html" + location.search + location.hash); } catch (e) {}
})();
