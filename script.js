import {
    marked
} from "https://cdn.jsdelivr.net/npm/marked/lib/marked.esm.js";


// Expose analyze to global scope for button onclick
window.analyze = analyze;


function applyTheme(theme) {

    const safeTheme =
        theme === "light"
            ? "light"
            : "dark";

    document.body.setAttribute(
        "data-theme",
        safeTheme
    );


    const toggle =
        document.getElementById(
            "themeToggle"
        );

    if (!toggle) return;


    const icon =
        toggle.querySelector(
            ".toggle-icon"
        );

    const label =
        toggle.querySelector(
            ".toggle-text"
        );


    if (safeTheme === "light") {

        toggle.setAttribute(
            "aria-label",
            "Switch to dark mode"
        );

        if (icon)
            icon.textContent = "🌙";

        if (label)
            label.textContent = "Dark mode";

    } else {

        toggle.setAttribute(
            "aria-label",
            "Switch to light mode"
        );

        if (icon)
            icon.textContent = "☀️";

        if (label)
            label.textContent = "Light mode";
    }
}


function initializeTheme() {

    const savedTheme =
        localStorage.getItem(
            "security-header-theme"
        );


    const systemPrefersLight =
        window
            .matchMedia(
                "(prefers-color-scheme: light)"
            )
            .matches;


    const preferredTheme =
        savedTheme ||
        (
            systemPrefersLight
                ? "light"
                : "dark"
        );


    applyTheme(
        preferredTheme
    );
}


function setupThemeToggle() {

    const toggle =
        document.getElementById(
            "themeToggle"
        );

    if (!toggle) return;


    toggle.addEventListener(
        "click",
        () => {

            const nextTheme =
                document.body
                    .getAttribute(
                        "data-theme"
                    ) === "light"
                    ? "dark"
                    : "light";


            localStorage.setItem(
                "security-header-theme",
                nextTheme
            );


            applyTheme(
                nextTheme
            );
        }
    );
}


/*
 * Existing raw-header modal functionality
 */

function openRawHeadersModal(headers) {

    const modal =
        document.getElementById(
            "rawHeadersModal"
        );

    const content =
        document.getElementById(
            "rawHeadersContent"
        );


    if (!modal || !content)
        return;


    const formattedHeaders =
        Object.entries(
            headers || {}
        )
        .sort(
            ([a], [b]) =>
                a.localeCompare(b)
        )
        .map(
            ([key, value]) =>
                `${key}: ${value}`
        )
        .join("\n");


    content.textContent =
        formattedHeaders ||
        "No headers returned.";


    modal.classList.add(
        "visible"
    );


    modal.setAttribute(
        "aria-hidden",
        "false"
    );
}


function closeRawHeadersModal() {

    const modal =
        document.getElementById(
            "rawHeadersModal"
        );


    if (!modal)
        return;


    modal.classList.remove(
        "visible"
    );


    modal.setAttribute(
        "aria-hidden",
        "true"
    );
}


function bindRawHeadersModal() {

    const modal =
        document.getElementById(
            "rawHeadersModal"
        );


    if (!modal)
        return;


    const closeButton =
        modal.querySelector(
            ".terminal-close"
        );


    if (closeButton) {

        closeButton.addEventListener(
            "click",
            closeRawHeadersModal
        );
    }


    modal.addEventListener(
        "click",
        (event) => {

            if (
                event.target === modal
            ) {

                closeRawHeadersModal();
            }
        }
    );


    document.addEventListener(
        "keydown",
        (event) => {

            if (
                event.key === "Escape"
                &&
                modal.classList.contains(
                    "visible"
                )
            ) {

                closeRawHeadersModal();
            }
        }
    );
}


/*
 * Small helper for safely displaying
 * server-returned values.
 */

function escapeHtml(value) {

    return String(
        value ?? ""
    )
    .replace(
        /&/g,
        "&amp;"
    )
    .replace(
        /</g,
        "&lt;"
    )
    .replace(
        />/g,
        "&gt;"
    )
    .replace(
        /"/g,
        "&quot;"
    )
    .replace(
        /'/g,
        "&#039;"
    );
}


/*
 * NEW:
 * Build the additional analysis section.
 */

function buildExtendedResults(data) {

    const details =
        data.header_details || {};


    const entries =
        Object.entries(
            details
        );


    const present =
        entries.filter(
            ([, item]) =>
                item.status === "PRESENT"
        ).length;


    const missing =
        entries.filter(
            ([, item]) =>
                item.status === "MISSING"
        ).length;


    const weak =
        entries.filter(
            ([, item]) =>
                item.status === "WEAK"
        ).length;


    const score =
        data.security_score ?? 0;


    const response =
        data.response || {};


    const cors =
        data.cors || {};


    const cookies =
        data.cookies || [];


    const cache =
        data.cache || {};


    const disclosure =
        data.information_disclosure || {};


    let html = `

        <div class="extended-results">


            <div class="score-row">

                <div class="score-card">

                    <strong>
                        ${escapeHtml(score)}/100
                    </strong>

                    <span>
                        Security Score
                    </span>

                </div>


                <div class="score-card">

                    <strong class="present">
                        ${present}
                    </strong>

                    <span>
                        Present
                    </span>

                </div>


                <div class="score-card">

                    <strong class="weak">
                        ${weak}
                    </strong>

                    <span>
                        Weak
                    </span>

                </div>


                <div class="score-card">

                    <strong class="missing">
                        ${missing}
                    </strong>

                    <span>
                        Missing
                    </span>

                </div>

            </div>


            <h2>
                Header Details
            </h2>


            <div class="header-details">
    `;


    for (
        const [header, item]
        of entries
    ) {

        let statusClass =
            "present";


        if (
            item.status ===
            "MISSING"
        ) {

            statusClass =
                "missing";

        } else if (
            item.status ===
            "WEAK"
        ) {

            statusClass =
                "weak";
        }


        html += `

            <div class="header-item">

                <div>

                    <strong>
                        ${escapeHtml(header)}
                    </strong>

                    &nbsp;

                    <span
                        class="${statusClass}"
                    >
                        ${escapeHtml(item.status)}
                    </span>

                </div>


                <small>

                    ${escapeHtml(
                        item.severity
                    )}

                    ·

                    ${escapeHtml(
                        item.category
                    )}

                </small>


                ${
                    item.value
                        ? `
                            <div class="header-value">
                                ${escapeHtml(
                                    item.value
                                )}
                            </div>
                          `
                        : ""
                }


                ${
                    item.status !== "PRESENT"
                        ? `
                            <div class="recommendation">
                                ${escapeHtml(
                                    item.recommendation
                                )}
                            </div>
                          `
                        : ""
                }

            </div>

        `;
    }


    html += `

            </div>


            <h2>
                Response Information
            </h2>


            <div class="response-info">

                <p>

                    <strong>
                        Status:
                    </strong>

                    ${escapeHtml(
                        response.status_code ??
                        data.status_code
                    )}

                    ${escapeHtml(
                        response.reason ?? ""
                    )}

                </p>


                <p>

                    <strong>
                        HTTP Version:
                    </strong>

                    ${escapeHtml(
                        response.http_version ??
                        "Unknown"
                    )}

                </p>


                <p>

                    <strong>
                        Response Time:
                    </strong>

                    ${escapeHtml(
                        response.response_time_ms ??
                        "Unknown"
                    )}
                    ms

                </p>


                <p>

                    <strong>
                        Final URL:
                    </strong>

                    ${escapeHtml(
                        response.final_url ??
                        data.final_url
                    )}

                </p>


                <p>

                    <strong>
                        Redirects:
                    </strong>

                    ${escapeHtml(
                        data.redirect_count ??
                        0
                    )}

                </p>

            </div>


            <h2>
                Additional Checks
            </h2>


            <div class="response-info">

                <p>

                    <strong>
                        HTTPS:
                    </strong>

                    ${
                        data.transport?.https
                            ? "✓ Enabled"
                            : "✗ Not HTTPS"
                    }

                </p>


                <p>

                    <strong>
                        CORS:
                    </strong>

                    ${escapeHtml(
                        cors.status ??
                        "Not checked"
                    )}

                </p>


                <p>

                    <strong>
                        Cookies:
                    </strong>

                    ${cookies.length}
                    detected

                </p>


                <p>

                    <strong>
                        Cache-Control:
                    </strong>

                    ${
                        cache.configured
                            ? "Configured"
                            : "Not specified"
                    }

                </p>


                <p>

                    <strong>
                        Information Disclosure:
                    </strong>

                    ${escapeHtml(
                        disclosure.status ??
                        "Not checked"
                    )}

                </p>

            </div>


        </div>

    `;


    return html;
}


/*
 * YOUR EXISTING ANALYZE FUNCTION
 * with only the extended result inserted.
 */

async function analyze() {

    const pageShell =
        document.querySelector(
            ".page-shell"
        );

    if (pageShell) {
        pageShell.classList.add(
            "results-visible"
        );
    }

    window.scrollTo({
        top: 0,
        left: 0,
        behavior: "instant"
    });

    const url =
        document
            .getElementById(
                "urlInput"
            )
            .value;


    const resultDiv =
        document.getElementById(
            "result"
        );


    resultDiv.innerHTML =
        "Scanning...";


    try {

        const response =
            await fetch(
                "/analyze",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            url: url
                        })
                }
            );


        const data =
            await response.json();

        if (data.error) {
            resultDiv.innerHTML = `
                <div class="result-header-row">
                    <h2>Analysis Result</h2>
                </div>
                <p class="missing"><strong>Connection failed:</strong> ${escapeHtml(data.error)}</p>
                <p><strong>Target URL:</strong> ${escapeHtml(data.final_url || "Unknown")}</p>
            `;
            return;
        }

        let leftHtml = "";

        for (const header in data.analysis) {
            const status = data.analysis[header];

            leftHtml += `
                <p>
                    <strong>${escapeHtml(header)}</strong>:
                    <span class="${status === "MISSING" ? "missing" : "present"}">
                        ${escapeHtml(status)}
                    </span>
                </p>
            `;
        }

        leftHtml += buildExtendedResults(data);

        const aiHtml = marked.parse(data.ai_analysis);

        resultDiv.innerHTML = `
            <div class="results-grid">
                <div class="analysis-panel left-panel">
                    <div class="panel-header">
                        <h2>Security Summary</h2>
                        <button class="raw-header-btn" type="button">Raw Headers</button>
                    </div>
                    <div class="panel-content">
                        ${leftHtml}
                    </div>
                </div>

                <div class="analysis-panel ai-analysis">
                    <div class="panel-header">
                        <h2>AI Risk Analysis</h2>
                    </div>
                    <div class="panel-content">
                        ${aiHtml}
                    </div>
                </div>
            </div>
        `;

        const rawButton =
            resultDiv.querySelector(
                ".raw-header-btn"
            );


        if (rawButton) {

            rawButton.addEventListener(
                "click",
                () => {

                    openRawHeadersModal(
                        data.raw_headers || {}
                    );

                }
            );
        }


    } catch (error) {

        resultDiv.innerHTML =
            "Error analyzing URL.";

        console.error(
            error
        );
    }
}


/*
 * Existing initialization
 */

initializeTheme();

setupThemeToggle();

bindRawHeadersModal();
