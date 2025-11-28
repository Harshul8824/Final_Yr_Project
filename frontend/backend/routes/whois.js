const router = require('express').Router();
const whoisjson = require('whois-json')
const dns = require('dns');
const utils = require('../utilities/utils')

// Note: dns.setDefaultTimeout is not available in Node.js
// We'll handle timeouts manually in the code

/**
 * Sanitize and validate host input
 * @param {String} host 
 */
function sanitizeHost(host) {
    if (!host || typeof host !== 'string') {
        return null;
    }
    
    // Remove any potentially dangerous characters
    host = host.trim();
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
        /[<>'"&]/g,  // HTML/XML injection
        /javascript:/gi,  // JavaScript injection
        /data:/gi,  // Data URI
        /vbscript:/gi,  // VBScript
        /onload/gi,  // Event handlers
        /script/gi,  // Script tags
        /eval/gi,  // Eval function
        /expression/gi  // CSS expression
    ];
    
    for (let pattern of suspiciousPatterns) {
        if (pattern.test(host)) {
            return null;
        }
    }
    
    // Check length
    if (host.length > 253) { // Max domain length
        return null;
    }
    
    return host;
}

/**
 * Validate host format
 * @param {String} host 
 */
function validateHost(host) {
    // Check for valid IP address
    if (utils.isValidIPaddress(host)) {
        return true;
    }
    
    // Check for valid domain format
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(host);
}

/**
 * DNS lookup with timeout
 * @param {String} host 
 * @param {Number} timeoutMs 
 */
function dnsLookupWithTimeout(host, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error('DNS lookup timeout'));
        }, timeoutMs);

        dns.lookup(host, (err, address, IPfamily) => {
            clearTimeout(timeout);
            if (err) {
                reject(err);
            } else {
                resolve({ address, IPfamily });
            }
        });
    });
}

router.route('/getrecord').post(async(req, res) => {
    // Set response timeout
    res.setTimeout(30000, () => {
        if (!res.headersSent) {
            res.status(408).json({ 
                msg: "Request timeout. Please try again with a valid host.", 
                error: "TIMEOUT" 
            });
        }
    });

    try {
        // Validate request body
        if (!req.body || typeof req.body !== 'object') {
            return res.status(400).json({ 
                msg: "Invalid request body. Please provide a valid JSON object.",
                error: "INVALID_BODY"
            });
        }

        let host = req.body.host;
        
        // Sanitize input
        host = sanitizeHost(host);
        if (!host) {
            return res.status(400).json({ 
                msg: "Invalid or suspicious host input. Please provide a valid hostname or IP address.",
                error: "INVALID_HOST"
            });
        }

        // Validate host format
        if (!validateHost(host)) {
            return res.status(400).json({ 
                msg: "Invalid host format. Please provide a valid hostname or IP address.",
                error: "INVALID_FORMAT"
            });
        }

        // Extract hostname if it's a URL
        if (!utils.isValidIPaddress(host)) {
            host = utils.extractHostname(host);
            if (!host) {
                return res.status(400).json({ 
                    msg: "Could not extract valid hostname from input.",
                    error: "EXTRACTION_FAILED"
                });
            }
        }

        console.log(`Processing WHOIS request for: ${host}`);

        // Get WHOIS data with timeout
        const whoisPromise = whoisjson(host);
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('WHOIS lookup timeout')), 15000)
        );

        const result = await Promise.race([whoisPromise, timeoutPromise]);

        if (!result) {
            return res.status(404).json({ 
                msg: "No WHOIS data found for the provided host.",
                error: "NO_DATA"
            });
        }

        // Get DNS information with timeout
        try {
            const dnsResult = await dnsLookupWithTimeout(host, 5000);
            result.hostingIPAddr = dnsResult.address;
            result.hostingIPFamily = dnsResult.IPfamily;
        } catch (dnsError) {
            console.log(`DNS lookup failed for ${host}:`, dnsError.message);
            result.hostingIPAddr = null;
            result.hostingIPFamily = null;
            result.dnsError = "DNS lookup failed";
        }

        res.json(result);

    } catch (error) {
        console.error('WHOIS Error:', error);
        
        if (error.message.includes('timeout')) {
            res.status(408).json({ 
                msg: "Request timeout. The host might be unreachable or invalid.",
                error: "TIMEOUT",
                details: error.message
            });
        } else if (error.message.includes('ENOTFOUND') || error.message.includes('ENODATA')) {
            res.status(404).json({ 
                msg: "Host not found. Please check the hostname or IP address.",
                error: "HOST_NOT_FOUND",
                details: error.message
            });
        } else {
            res.status(500).json({ 
                msg: "An error occurred while processing the request. Please try again later.",
                error: "INTERNAL_ERROR",
                details: error.message
            });
        }
    }
});

module.exports = router;