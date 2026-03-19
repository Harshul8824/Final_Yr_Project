const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { requireAuth } = require('../middleware/auth');

// Helper function to load IPs from data files into a Set
const loadIps = (filename) => {
    try {
        const filePath = path.join(__dirname, '..', 'data', filename);
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            const ipArray = data.split(/\r?\n/).map(ip => ip.trim()).filter(ip => ip.length > 0);
            return new Set(ipArray);
        }
    } catch (e) {
        console.error(`Error loading ${filename}:`, e.message);
    }
    return new Set();
};

const vpnIps = loadIps('vpn-ips.txt');
const threatIps = loadIps('threat-ips.txt');

router.post('/processfile', requireAuth, async (req, res) => {
    try {
        if (!req.files || !req.files.ipFile) {
            return res.status(400).json({ msg: 'No file uploaded' });
        }

        const ipFile = req.files.ipFile;
        const fileContent = ipFile.data.toString('utf8');
        const lines = fileContent.split(/\r?\n/);
        
        let ips = lines.map(line => {
            // Support simple CSV parsing (take first column)
            const parts = line.split(',');
            return parts[0].trim();
        }).filter(ip => ip.length > 0);

        if (ips.length === 0) {
            return res.status(400).json({ msg: 'Uploaded file is empty or contains no valid IPs' });
        }

        if (ips.length > 500) {
            return res.status(400).json({ msg: 'Maximum 500 IPs allowed per file to prevent rate limits' });
        }

        const apiKey = process.env.IP_QUALITY_SCORE_API_KEY;

        const processIp = async (ip) => {
            let isVPN = false;
            let threatType = null;
            let riskLevel = "Low";
            let details = [];

            // 1. VPN List Check
            if (vpnIps.has(ip)) {
                isVPN = true;
                riskLevel = "Medium";
                details.push("Found in VPN list");
            }

            // 2. Threat List Check
            if (threatIps.has(ip)) {
                threatType = "Known Threat";
                riskLevel = "High";
                details.push("Found in internal Threat database");
            }

            // 3. IPQualityScore API (Optional via Env)
            if (apiKey) {
                try {
                    // Timeout set to keep batch execution reasonable
                    const response = await axios.get(`https://www.ipqualityscore.com/api/json/ip/${apiKey}/${ip}`, { timeout: 3000 });
                    const data = response.data;
                    
                    if (data.success) {
                        if (data.vpn || data.proxy || data.tor) {
                            isVPN = true;
                            if (data.tor) threatType = threatType || "TOR Edge Node";
                            else if (data.proxy) threatType = threatType || "Proxy Server";
                            else threatType = threatType || "VPN";
                            
                            details.push(`External Intel: Fraud Score ${data.fraud_score}`);
                        }
                        
                        // Override risk level based on score
                        if (data.fraud_score >= 80) {
                            riskLevel = "High";
                            threatType = threatType || "High Risk IP";
                        } else if (data.fraud_score >= 50 && riskLevel === "Low") {
                            riskLevel = "Medium";
                        }
                    }
                } catch (apiErr) {
                    console.error(`IPQualityScore api error for ${ip}:`, apiErr.message);
                }
            }

            if (details.length === 0) {
                details.push("Clean IP");
            }

            return {
                ip: ip,
                isVPN: isVPN,
                threatType: threatType,
                riskLevel: riskLevel,
                details: details.join(' | ')
            };
        };

        const promises = ips.map(ip => processIp(ip));
        const results = await Promise.all(promises);

        res.status(200).json(results);
    } catch (err) {
        console.error("Batch process endpoint error:", err);
        res.status(500).json({ msg: "Some error occured. Please try again later", err: err.message });
    }
});

module.exports = router;
