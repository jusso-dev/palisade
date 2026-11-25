// The version switcher in theme/header.hbs. The published site has one
// directory per version (`latest/`, `v0.1/`, ...) and `versions.json` at
// its root, written by `cargo xtask docs assemble`. A local build has
// neither, and the switcher stays hidden.
(function () {
    "use strict";
    const select = document.getElementById("palisade-version-select");
    if (!select || typeof path_to_root === "undefined") {
        return;
    }
    // This page's URL below the version directory, and the site root. At
    // the book's root `path_to_root` is "", and `new URL("", page)` is the
    // page itself, so resolve "./" instead.
    const book = new URL(path_to_root || "./", window.location.href);
    const site = new URL("../", book);
    const current = book.pathname.replace(/\/$/, "").split("/").pop();
    const page = window.location.href.slice(book.href.length);
    fetch(new URL("versions.json", site))
        .then(function (response) {
            return response.ok ? response.json() : [];
        })
        .then(function (versions) {
            if (!Array.isArray(versions) || versions.indexOf(current) < 0) {
                return;
            }
            versions.forEach(function (name) {
                if (!/^(latest|v[0-9]+\.[0-9]+)$/.test(name)) {
                    return;
                }
                const option = document.createElement("option");
                option.value = name;
                option.textContent = name;
                option.selected = name === current;
                select.appendChild(option);
            });
            select.hidden = false;
            select.addEventListener("change", function () {
                window.location.href = new URL(select.value + "/" + page, site).href;
            });
        })
        .catch(function () {});
})();
