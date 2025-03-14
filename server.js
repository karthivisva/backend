const express = require("express");
const cors = require("cors");
const punycode = require("punycode/");

const app = express();
app.use(express.json());

// Enable CORS (Modify origin as needed for security)
app.use(cors({ origin: "*" }));

const blacklistedDomains = ["phishing.com", "scam-site.tk", "fakebank.xyz"];
const suspiciousKeywords = ["login", "secure", "bank", "verify", "update", "free", "cheap", "offer"];
const riskyExtensions = [".tk", ".ml", ".cf", ".gq", ".xyz"];
const randomCharPattern = /^[a-z]{10,}\.com$/; // Detects nonsense domains

app.post("/analyze", (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL is required" });

    let riskScore = 0;
    let reasons = [];

    let normalizedUrl = url.toLowerCase();
    const domainOnly = normalizedUrl.replace(/^https?:\/\//, "").split("/")[0]; // Extract domain part

    if (blacklistedDomains.some(domain => normalizedUrl.includes(domain))) {
        riskScore += 40;
        reasons.push("Domain appears in a known blacklist");
    }

    suspiciousKeywords.forEach(keyword => {
        if (normalizedUrl.includes(keyword)) {
            riskScore += 10;
            reasons.push(`Contains suspicious keyword: "${keyword}"`);
        }
    });

    riskyExtensions.forEach(ext => {
        if (normalizedUrl.endsWith(ext)) {
            riskScore += 20;
            reasons.push(`Uses a risky domain extension: "${ext}"`);
        }
    });

    if (randomCharPattern.test(domainOnly)) {
        riskScore += 50;
        reasons.push("Domain contains random, unrecognizable characters");
    }

    const ipPattern = /^(http[s]?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/;
    if (ipPattern.test(url)) {
        riskScore += 30;
        reasons.push("Uses direct IP address instead of domain");
    }

    if (domainOnly.split(".").length > 3) {
        riskScore += 15;
        reasons.push("Too many subdomains, could be phishing");
    }

    const decodedDomain = punycode.toUnicode(normalizedUrl);
    if (decodedDomain !== normalizedUrl) {
        riskScore += 25;
        reasons.push("URL contains potential homoglyph attack");
    }

    if (reasons.length === 0) reasons.push("No obvious suspicious activity detected.");

    let status = riskScore > 50 ? "Suspicious" : "Safe";

    res.json({ url, status, riskScore: Math.min(riskScore, 100), reasons });
});

// Run server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
