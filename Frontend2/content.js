// ==UserScript==
// @name         Malicious URL Detector
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Highlights and warns about malicious URLs using Flask API
// @author       You
// @match        *://*/*
// @grant        none
// ==/UserScript==

const API_ENDPOINT = "http://localhost:5000/predict";

// Extract base domain with protocol
function extractDomainWithProtocol(url) {
  try {
    const match = url.match(/^(https?:\/\/[^\/]*?\.(com|org|net|gov|edu|info|io|co|in|us|uk|me|tech|ai|xyz|biz|top|site|pro))/i);
    return match ? match[0] : null;
  } catch (e) {
    return null;
  }
}


async function checkUrl(url, useDomainExtraction = true) {
  const cleanedUrl = useDomainExtraction ? extractDomainWithProtocol(url) : url;
  if (!cleanedUrl) return false;

  console.log("→ Sending to Flask:", cleanedUrl);
  try {
    const res = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: cleanedUrl })
    });
    const data = await res.json();
    return data.prediction === "Malicious";
  } catch (err) {
    console.error("Error while checking URL:", cleanedUrl, err);
    return false;
  }
}


// 🚨 Overlay for malicious pages
function showWarningOverlay() {
  const overlay = document.createElement("div");
  overlay.style.cssText = `
    position: fixed;
    top: 0; left: 0;
    width: 100vw; height: 100vh;
    background: rgba(0, 0, 0, 0.95);
    color: white;
    font-size: 22px;
    z-index: 999999;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
  `;
  overlay.innerHTML = `
    <div style="margin-bottom: 20px;">⚠️ Warning: Malicious Website Detected!</div>
    <div>
      <button id="goBack" style="margin-right: 15px; padding: 10px 20px;">Go Back</button>
      <button id="continue" style="padding: 10px 20px;">Proceed Anyway</button>
    </div>
  `;
  document.body.appendChild(overlay);
  document.getElementById("goBack").onclick = () => window.history.back();
  document.getElementById("continue").onclick = () => overlay.remove();
}

// ✅ URL checker
function isValidUrl(str) {
  try {
    new URL(str);
    return true;
  } catch (_) {
    return false;
  }
}

// 🔍 QR Code Scanner
// async function scanQrFromImage(imgElement) {
//   try {
//     const canvas = document.createElement("canvas");
//     canvas.width = imgElement.naturalWidth;
//     canvas.height = imgElement.naturalHeight;

//     const ctx = canvas.getContext("2d");
//     ctx.drawImage(imgElement, 0, 0);
//     const dataURL = canvas.toDataURL("image/png"); // Base64-encoded image

//     const response = await fetch(API_ENDPOINT + "/qr", {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ image: dataURL })
//     });

//     const data = await response.json();
//     return data.text || null;
//   } catch (err) {
//     console.error("QR scan failed:", err);
//     return null;
//   }
// }


async function scanQrFromImage(imgElement) {
  try {
    // Create canvas
    const canvas = document.createElement("canvas");
    canvas.width = imgElement.naturalWidth;
    canvas.height = imgElement.naturalHeight;

    const ctx = canvas.getContext("2d");
    ctx.drawImage(imgElement, 0, 0);

    // Try to use the original image type if available
    const mimeType = imgElement.currentSrc?.split(";")[0]?.split(":")[1] || "image/png";
    const dataURL = canvas.toDataURL(mimeType);

    // Log the base64 image being sent
    console.log("📤 Sending image to Flask QR endpoint:");
    console.log(dataURL);

    const response = await fetch(API_ENDPOINT + "/qr", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image: dataURL })
    });

    const data = await response.json();
    return data.text || null;
  } catch (err) {
    console.error("QR scan failed:", err);
    return null;
  }
}


// Helper to get visible text nodes
function getVisibleTextNodes() {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode: node => {
      const parent = node.parentElement;
      const style = window.getComputedStyle(parent);
      const isVisible = !!(parent.offsetWidth || parent.offsetHeight || parent.getClientRects().length);
      return isVisible && style.visibility !== 'hidden' && style.display !== 'none'
        ? NodeFilter.FILTER_ACCEPT
        : NodeFilter.FILTER_REJECT;
    }
  });

  const nodes = [];
  while (walker.nextNode()) {
    nodes.push(walker.currentNode);
  }
  return nodes;
}

const urlRegex = /(https?:\/\/[^\s]+)/g;
const scannedDomains = new Set();

(async function main() {
  // 1. Check current page URL
  const isPageMalicious = await checkUrl(window.location.href); // ✅ uses extractDomainWithProtocol

  if (isPageMalicious) {
    showWarningOverlay();
  }

  // 2. Scan visible text nodes for URLs
  const textNodes = getVisibleTextNodes();
  for (const node of textNodes) {
    const text = node.nodeValue;
    const urls = text.match(urlRegex);

    if (urls) {
      for (const url of urls) {
        const baseDomain = extractDomainWithProtocol(url);
        if (!baseDomain || scannedDomains.has(baseDomain)) continue;

        scannedDomains.add(baseDomain);
        const malicious = await checkUrl(url,false);
        if (malicious) {
          const span = document.createElement("span");
          span.style.color = "red";
          span.style.border = "1px solid red";
          span.style.padding = "2px 4px";
          span.style.borderRadius = "4px";
          span.title = "⚠️ Malicious URL";
          span.textContent = url;

          const parts = text.split(url);
          const after = document.createTextNode(parts[1] || "");
          const parent = node.parentNode;
          parent.replaceChild(after, node);
          parent.insertBefore(span, after);
          parent.insertBefore(document.createTextNode(parts[0]), span);
        }
      }
    }
  }

  // 3. Scan QR codes on page
  const images = document.querySelectorAll("img");
  for (const img of images) {
    const result = await scanQrFromImage(img);
    if (result && isValidUrl(result)) {
      const malicious = await checkUrl(result,false);
      if (malicious) {
        img.style.border = "5px solid red";
        img.title = "QR code contains malicious URL";
      }
    }
  }
})();
