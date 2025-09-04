
document.addEventListener("DOMContentLoaded", async function () {
    const scriptTag = document.currentScript || document.querySelector('script[src*="command-palette.js"]');
    const jsonUrl = scriptTag?.dataset?.json;

    if (!jsonUrl) {
        console.error("No data-json attribute found on command-palette script tag.");
        return;
    }

    const input = document.querySelector(".command-palette-input");
    const resultBox = document.querySelector('.command-palette-result');
    const resultCount = document.querySelector('.command-palette-result-count');
    const resultList = document.querySelector('.command-palette-result-list');
    const backdrop = document.querySelector('.command-palette-backdrop');
    const inputWrapper = document.querySelector('.command-palette-input-wrapper');
    const commandButton = document.querySelector('.command-palette-button');
    const commandCloser = document.querySelector('.command-palette-closer');

    let allLinks = [];

    async function fetchLinks() {
        try {
            const response = await fetch(jsonUrl);
            if (!response.ok) throw new Error(`Failed to fetch links from ${jsonUrl}`);
            allLinks = await response.json();
            if (!Array.isArray(allLinks)) throw new Error("Invalid data format: expected an array of links.");
        } catch (err) {
            console.error("Command Palette: Fetch error:", err);
        }
    }

    function filterLinks(query) {
        const lowerQuery = query.toLowerCase();
        return allLinks.filter(link =>
            link.label.toLowerCase().includes(lowerQuery)
        );
    }

    function getCommandIcon(url) {

        switch (url) {

            case "/user":
                return "bx bx-user fs-5"

            case "/user/add":
                return "bx bx-plus fs-5"

            case "/user/change-password":
                return "bx bx-lock fs-5"

            case "/user/logout":
                return "bx bx-power-off fs-5"

            case "/user/group/list":
                return "bx bx-grid-alt fs-5"

            case "/user/group/add":
                return "bx bx-plus fs-5"

            default:
                return "bx bx-search fs-5"
        }

    }

    function renderResults(filtered) {
        resultList.textContent = "";

        if (filtered.length === 0) {
            resultCount.textContent = "0 results found";
            resultList.style.display = "none";
            return;
        }

        function isSafeUrl(url) {
            try {
                const parsed = new URL(url, window.location.origin);
                return ["http:", "https:"].includes(parsed.protocol);
            } catch {
                return false;
            }
        }

        filtered.forEach(link => {
            const item = document.createElement("a");

            if (link.url === "/user/logout") {
                item.href = "#";
                item.setAttribute("type", "logout")
                item.addEventListener("click", e => {
                    e.preventDefault();
                    document.getElementById("logout-form").submit();
                });
            } else if (isSafeUrl(link.url)) {
                item.href = link.url;
                item.target = "_blank";
            } else {
                item.href = "#";
                console.warn("Blocked unsafe link:", link.url);
            }

            item.className = "command-palette-result-item";

            const div = document.createElement("div");
            div.className = "d-flex align-items-center gap-3";

            const icon = document.createElement("i");
            icon.className = getCommandIcon(link.url);

            const span = document.createElement("span");
            span.textContent = link.label;

            div.appendChild(icon);
            div.appendChild(span);
            item.appendChild(div);
            resultList.appendChild(item);
        });

        resultCount.textContent = `${filtered.length} result${filtered.length > 1 ? 's' : ''} found`;
        resultBox.style.display = "block";
        resultList.style.display = "block";
    }

    function cleanup() {
        input.value = "";
        resultBox.style.display = "none";
        resultList.innerHTML = "";
        resultCount.textContent = "";
    }

    function showCommandPalette() {
        hideAllDropdowns();
        backdrop?.classList.add('show');
        inputWrapper?.classList.add('show');
        input?.focus();
        input.value = '';
    }

    function hideCommandPalette() {
        hideAllDropdowns();
        backdrop?.classList.remove('show');
        inputWrapper?.classList.remove('show');
        input.value = '';
    }

    function hideAllDropdowns() {
        cleanup();
    }

    // Input handlers
    let debounceTimer;
    input?.addEventListener("input", () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            const query = input.value.trim();
            if (!query) {
                cleanup();
                return;
            }
            const filtered = filterLinks(query);
            renderResults(filtered);
        }, 150);
    });

    input?.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            const activeItem = document.querySelector('.command-palette-result-item.active');
            if (activeItem) {
                e.preventDefault();
                if (activeItem.getAttribute("type") === "logout") {
                    document.getElementById('logout-form').submit();
                } else {
                    window.open(activeItem.href, '_blank');
                }
                hideCommandPalette();
            }
        } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            const items = document.querySelectorAll('.command-palette-result-item');
            let activeIndex = Array.from(items).findIndex(item => item.classList.contains('active'));

            if (e.key === "ArrowDown") {
                activeIndex = (activeIndex + 1) % items.length;
            } else {
                activeIndex = (activeIndex - 1 + items.length) % items.length;
            }

            items.forEach(item => item.classList.remove('active'));
            if (items[activeIndex]) {
                items[activeIndex].classList.add('active');
                items[activeIndex].scrollIntoView({
                    block: 'nearest',
                    behavior: 'smooth'
                });
            }
        }
    });

    document.addEventListener("click", (e) => {
        if (!inputWrapper.contains(e.target)) {
            hideCommandPalette();
        }
    });

    commandButton?.addEventListener('click', (e) => {
        showCommandPalette();
        e.stopPropagation();
    });

    commandCloser?.addEventListener('click', () => hideCommandPalette());

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && inputWrapper?.classList.contains("show")) {
            hideCommandPalette();
        } else if (e.ctrlKey && e.key === "\\") {
            showCommandPalette();
        }
    });

    // Load links once on page load
    fetchLinks();
});
