(() => {
  "use strict";

  const TOOLTIP_HOST_CLASS = "website-checker-tooltip-host";
  const TOOLTIP_OFFSET = 12;
  const VIEWPORT_MARGIN = 8;
  // 보안 판정값이 아니라 긴 URL을 눈에 띄게 표시하기 위한 단순 기준이다.
  const LONG_URL_THRESHOLD = 150;

  let hoveredLink = null;
  let tooltipHost = null;
  let tooltipExplanationElement = null;

  function isIpAddress(hostname) {
    const value = hostname.replace(/^\[|\]$/g, "");
    const ipv4Parts = value.split(".");
    const isIpv4 = ipv4Parts.length === 4 && ipv4Parts.every((part) =>
      /^\d{1,3}$/.test(part) && Number(part) <= 255
    );
    // URL 파싱을 통과한 hostname에서 콜론이 있으면 IPv6 형태로 간주할 수 있다.
    const isIpv6 = value.includes(":") && /^[0-9a-f:.]+$/i.test(value);
    return isIpv4 || isIpv6;
  }

  function countSubdomains(hostname, usesIpAddress) {
    if (usesIpAddress) return 0;

    const labels = hostname.replace(/\.$/, "").split(".").filter(Boolean);
    if (labels.length <= 2) return 0;

    // Public Suffix List 없이 사용하는 간단한 휴리스틱이다. co.kr, co.uk 등
    // 흔한 2단계 suffix만 보정하므로 모든 registrable domain에 정확하지는 않다.
    const commonSecondLevelSuffixes = new Set([
      "co.kr", "or.kr", "go.kr", "ac.kr", "co.uk", "org.uk", "gov.uk",
      "com.au", "net.au", "org.au", "co.jp", "com.br"
    ]);
    const suffix = labels.slice(-2).join(".").toLowerCase();
    const registrableLabelCount = commonSecondLevelSuffixes.has(suffix) ? 3 : 2;
    return Math.max(0, labels.length - registrableLabelCount);
  }

  function findExplicitPort(urlText) {
    // URL 객체는 명시된 기본 포트(:80/:443)를 빈 문자열로 정규화하므로 원문도 확인한다.
    const authorityMatch = String(urlText).match(
      /^(?:[a-z][a-z\d+.-]*:)?\/\/(?:[^@/?#]*@)?(?:\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?#]|$)/i
    );
    return authorityMatch?.[1] ?? "";
  }

  function analyzeUrl(urlText) {
    try {
      const url = new URL(urlText, document.baseURI);
      if (url.protocol !== "http:" && url.protocol !== "https:") return null;

      const usesIpAddress = isIpAddress(url.hostname);
      const explicitPort = findExplicitPort(urlText);
      const port = explicitPort || url.port;
      const defaultPort = url.protocol === "https:" ? "443" : "80";
      const hyphenCount = (url.hostname.match(/-/g) || []).length;
      const digitCount = (url.hostname.match(/\d/g) || []).length;

      return {
        hostname: url.hostname,
        fullUrl: url.href,
        protocol: url.protocol,
        pathname: url.pathname,
        port,
        isHttps: url.protocol === "https:",
        usesIpAddress,
        hasPunycode: url.hostname.toLowerCase().includes("xn--"),
        urlLength: url.href.length,
        isLongUrl: url.href.length >= LONG_URL_THRESHOLD,
        hasUnusualPort: Boolean(port && port !== defaultPort),
        subdomainCount: countSubdomains(url.hostname, usesIpAddress),
        hyphenCount,
        digitCount,
        suspiciousCharacterCount: hyphenCount + digitCount,
        hasUserInfo: Boolean(url.username || url.password),
        hasAtCharacter: String(urlText).includes("@")
      };
    } catch {
      return null;
    }
  }

  // 분석할 수 없는 링크를 거르고 상대 URL은 현재 페이지 기준으로 분석한다.
  function getLinkAnalysis(link) {
    const rawHref = link.getAttribute("href")?.trim();

    if (
      !rawHref ||
      rawHref === "#" ||
      rawHref.startsWith("#") ||
      /^(javascript|mailto|tel):/i.test(rawHref)
    ) {
      return null;
    }

    return analyzeUrl(rawHref);
  }

  function getMetaDescription() {
    return document.querySelector('meta[name="description" i]')
      ?.getAttribute("content")
      ?.trim() || "";
  }

  function getLinkText(link) {
    // 이미지 링크처럼 보이는 텍스트가 없을 때는 접근성 레이블도 활용한다.
    return (link.innerText || link.getAttribute("aria-label") || "")
      .replace(/\s+/g, " ")
      .trim();
  }

  // URL 분석 결과와 현재 열려 있는 페이지에서 얻은 정보만 구조화한다.
  // 대상 링크의 외부 페이지를 fetch하거나 방문하지 않는다.
  function buildEvidence(link, urlAnalysis) {
    return {
      schemaVersion: 1,
      target: {
        url: urlAnalysis.fullUrl,
        hostname: urlAnalysis.hostname,
        linkText: getLinkText(link)
      },
      urlAnalysis: {
        protocol: urlAnalysis.protocol,
        pathname: urlAnalysis.pathname,
        port: urlAnalysis.port,
        isHttps: urlAnalysis.isHttps,
        usesIpAddress: urlAnalysis.usesIpAddress,
        hasPunycode: urlAnalysis.hasPunycode,
        urlLength: urlAnalysis.urlLength,
        isLongUrl: urlAnalysis.isLongUrl,
        hasUnusualPort: urlAnalysis.hasUnusualPort,
        subdomainCount: urlAnalysis.subdomainCount,
        hyphenCount: urlAnalysis.hyphenCount,
        digitCount: urlAnalysis.digitCount,
        suspiciousCharacterCount: urlAnalysis.suspiciousCharacterCount,
        hasUserInfo: urlAnalysis.hasUserInfo,
        hasAtCharacter: urlAnalysis.hasAtCharacter
      },
      pageContext: {
        url: window.location.href,
        title: document.title,
        description: getMetaDescription()
      },
      // 향후 평판 서비스 등에서 수집한 근거를 담을 자리다.
      externalEvidence: [],
      metadata: {
        collectedAt: new Date().toISOString(),
        source: "browser-content-script"
      }
    };
  }

  // Explanation Provider의 경계다. 현재는 service worker의 placeholder만 호출하며
  // 어떤 모델이나 외부 API에도 연결하지 않는다.
  function requestExplanation(evidence) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "REQUEST_EXPLANATION", evidence },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            resolve({
              status: "unavailable",
              text: "아직 설명 분석기가 연결되지 않았습니다."
            });
            return;
          }

          resolve(response);
        }
      );
    });
  }

  function yesOrNo(value) {
    return value ? "예" : "아니오";
  }

  function appendRow(parent, label, value, isNotice = false) {
    const row = document.createElement("div");
    row.className = isNotice ? "row notice" : "row";

    const labelElement = document.createElement("span");
    labelElement.className = "label";
    labelElement.textContent = `${label}: `;

    const valueElement = document.createElement("span");
    valueElement.className = "value";
    valueElement.textContent = value;

    row.append(labelElement, valueElement);
    parent.appendChild(row);
  }

  function createSection(title) {
    const section = document.createElement("section");
    const heading = document.createElement("div");
    heading.className = "section-title";
    heading.textContent = title;
    section.appendChild(heading);
    return section;
  }

  function createTooltip(evidence) {
    const analysis = evidence.urlAnalysis;
    const host = document.createElement("div");
    host.className = TOOLTIP_HOST_CLASS;
    host.setAttribute("role", "tooltip");

    // Shadow DOM은 방문한 웹사이트의 스타일이 툴팁 내부에 섞이는 것을 막는다.
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      .card {
        box-sizing: border-box;
        width: max-content;
        max-width: min(400px, calc(100vw - 16px));
        max-height: calc(100vh - 16px);
        overflow-y: auto;
        padding: 12px;
        border: 1px solid #d8dee4;
        border-radius: 8px;
        background: #ffffff;
        color: #1f2328;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.18);
        font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        text-align: left;
      }
      .hostname { margin-bottom: 6px; font-size: 15px; font-weight: 700; overflow-wrap: anywhere; }
      .url { overflow-wrap: anywhere; color: #45515f; }
      section { margin-top: 11px; padding-top: 9px; border-top: 1px solid #eaeef2; }
      .section-title { margin-bottom: 5px; font-weight: 700; }
      .row { margin-top: 2px; overflow-wrap: anywhere; }
      .label { color: #57606a; }
      .value { font-weight: 500; }
      .notice { color: #9a6700; }
      .notice .label { color: inherit; font-weight: 700; }
      .explanation { color: #57606a; overflow-wrap: anywhere; }
    `;

    const card = document.createElement("div");
    card.className = "card";

    const hostname = document.createElement("div");
    hostname.className = "hostname";
    hostname.textContent = evidence.target.hostname;
    const url = document.createElement("div");
    url.className = "url";
    url.textContent = evidence.target.url;
    card.append(hostname, url);

    const urlSection = createSection("URL 정보");
    appendRow(urlSection, "Protocol", analysis.protocol.slice(0, -1).toUpperCase());
    appendRow(urlSection, "Hostname", evidence.target.hostname);
    appendRow(urlSection, "Pathname", analysis.pathname);
    appendRow(urlSection, "포트", analysis.port || "없음");
    card.appendChild(urlSection);

    const analysisSection = createSection("정적 분석");
    appendRow(analysisSection, "HTTPS 사용", yesOrNo(analysis.isHttps));
    appendRow(analysisSection, "IP 주소 직접 사용", yesOrNo(analysis.usesIpAddress));
    appendRow(analysisSection, "Punycode 사용", yesOrNo(analysis.hasPunycode));
    appendRow(analysisSection, "URL 길이", `${analysis.urlLength}자`);
    appendRow(analysisSection, "긴 URL", yesOrNo(analysis.isLongUrl));
    appendRow(analysisSection, "서브도메인 단계", String(analysis.subdomainCount));
    appendRow(analysisSection, "비표준 포트 사용", yesOrNo(analysis.hasUnusualPort));
    appendRow(analysisSection, "하이픈 개수", String(analysis.hyphenCount));
    appendRow(analysisSection, "숫자 문자 개수", String(analysis.digitCount));
    appendRow(analysisSection, "URL 사용자 정보 포함", yesOrNo(analysis.hasUserInfo), analysis.hasUserInfo);
    appendRow(analysisSection, "@ 문자 포함", yesOrNo(analysis.hasAtCharacter));
    card.appendChild(analysisSection);

    const notices = [];
    if (analysis.usesIpAddress) notices.push("IP 주소를 직접 사용하는 URL");
    if (analysis.hasPunycode) notices.push("Punycode hostname 사용");
    if (analysis.hasUserInfo) notices.push("URL에 사용자 정보 포함");
    if (analysis.hasUnusualPort) notices.push("비표준 포트 사용");
    if (analysis.isLongUrl) notices.push(`URL 길이가 ${LONG_URL_THRESHOLD}자 이상`);

    if (notices.length > 0) {
      const noticeSection = createSection("주의해서 볼 항목");
      for (const notice of notices) {
        const item = document.createElement("div");
        item.className = "row notice";
        item.textContent = `• ${notice}`;
        noticeSection.appendChild(item);
      }
      card.appendChild(noticeSection);
    }

    const explanationSection = createSection("사이트 설명");
    const explanation = document.createElement("div");
    explanation.className = "explanation";
    explanation.textContent = "설명 분석기 연결 상태를 확인하는 중입니다.";
    explanationSection.appendChild(explanation);
    card.appendChild(explanationSection);

    shadow.append(style, card);
    document.documentElement.appendChild(host);
    return { host, explanationElement: explanation };
  }

  function positionTooltip(link) {
    if (!tooltipHost) return;

    const linkRect = link.getBoundingClientRect();
    const tooltipRect = tooltipHost.getBoundingClientRect();
    let left = linkRect.left;
    let top = linkRect.bottom + TOOLTIP_OFFSET;

    left = Math.min(left, window.innerWidth - tooltipRect.width - VIEWPORT_MARGIN);
    left = Math.max(VIEWPORT_MARGIN, left);

    if (top + tooltipRect.height > window.innerHeight - VIEWPORT_MARGIN) {
      top = linkRect.top - tooltipRect.height - TOOLTIP_OFFSET;
    }
    top = Math.max(VIEWPORT_MARGIN, top);

    tooltipHost.style.left = `${left}px`;
    tooltipHost.style.top = `${top}px`;
  }

  function hideTooltip() {
    tooltipHost?.remove();
    tooltipHost = null;
    tooltipExplanationElement = null;
  }

  function showTooltip(link) {
    const analysis = getLinkAnalysis(link);
    if (!analysis) {
      hideTooltip();
      return;
    }

    // 같은 링크에서 mouseover가 반복되어도 DOM을 다시 만들지 않는다.
    if (tooltipHost && hoveredLink === link) {
      positionTooltip(link);
      return;
    }

    hideTooltip();
    const evidence = buildEvidence(link, analysis);
    const tooltip = createTooltip(evidence);
    tooltipHost = tooltip.host;
    tooltipExplanationElement = tooltip.explanationElement;
    positionTooltip(link);

    const createdHost = tooltipHost;
    requestExplanation(evidence).then((result) => {
      // 응답 전에 링크를 벗어났거나 다른 링크로 이동했으면 갱신하지 않는다.
      if (tooltipHost !== createdHost || !tooltipExplanationElement) return;
      tooltipExplanationElement.textContent = result.text;
      positionTooltip(link);
    });
  }

  document.addEventListener("mouseover", (event) => {
    const link = event.target.closest?.("a");
    hoveredLink = link;

    if (event.altKey && link) {
      showTooltip(link);
    } else {
      hideTooltip();
    }
  });

  document.addEventListener("mouseout", (event) => {
    if (!hoveredLink) return;

    const nextLink = event.relatedTarget?.closest?.("a") ?? null;
    if (nextLink !== hoveredLink) {
      hoveredLink = nextLink;
      hideTooltip();
    }
  });

  // 링크 위에 이미 마우스가 있는 상태에서 Alt를 누르는 경우도 지원한다.
  document.addEventListener("keydown", (event) => {
    if (event.key === "Alt" && hoveredLink) {
      showTooltip(hoveredLink);
    }
  });

  document.addEventListener("keyup", (event) => {
    if (event.key === "Alt") hideTooltip();
  });

  window.addEventListener("blur", hideTooltip);
  window.addEventListener("scroll", () => {
    if (tooltipHost && hoveredLink) positionTooltip(hoveredLink);
  }, { passive: true });
})();
