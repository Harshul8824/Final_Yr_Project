const router = require('express').Router();
const whoisjson = require('whois-json')
const dns = require('dns');
const utils = require('../utilities/utils')

// Note: dns.setDefaultTimeout is not available in Node.js
// We'll handle timeouts manually in the code

function firstDefined(...values) {
    for (const v of values) {
        if (v === null || v === undefined) continue;
        if (Array.isArray(v)) {
            if (v.length > 0 && v[0] !== undefined && v[0] !== null && v[0] !== '') return v[0];
            continue;
        }
        if (v !== '') return v;
    }
    return null;
}

function normalizeToIsoDate(value) {
    const raw = firstDefined(value);
    if (!raw) return null;

    // Some whois providers return arrays or strings with time; Date parsing handles most.
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) return null;

    // YYYY-MM-DD
    return d.toISOString().slice(0, 10);
}

function extractValueFromRaw(raw, labels) {
    const text = typeof raw === 'string' ? raw : Array.isArray(raw) ? raw.join('\n') : null;
    if (!text) return null;

    for (const label of labels) {
        // Common WHOIS formats:
        // "Creation Date: 1997-09-15T04:00:00Z"
        // "Registry Expiry Date: 2028-09-13T04:00:00Z"
        const re = new RegExp(`^\\s*${label}\\s*:\\s*(.+)\\s*$`, 'im');
        const m = text.match(re);
        if (m && m[1]) return m[1].trim();
    }
    return null;
}

function computeAgeYears(createdIsoDate) {
    if (!createdIsoDate) return null;
    const created = new Date(createdIsoDate);
    if (Number.isNaN(created.getTime())) return null;

    const now = new Date();
    const diffMs = now.getTime() - created.getTime();
    if (diffMs < 0) return null;

    const years = Math.floor(diffMs / (365.25 * 24 * 60 * 60 * 1000));
    return `${years} years`;
}


function buildSimplifiedWhois({ host, whoisResult, dnsResult }) {
    const rawText = whoisResult?.raw ?? whoisResult?.text ?? whoisResult?.data ?? null;
    console.log(whoisResult);
    const registrar = firstDefined(
        whoisResult?.registrar,
        whoisResult?.registrarName,
        whoisResult?.sponsoringRegistrar,
        whoisResult?.Registrar,
        whoisResult?.['Registrar'],
        extractValueFromRaw(rawText, ['Registrar', 'Sponsoring Registrar'])
    );

    const organization = firstDefined(
        whoisResult?.orgName,
        whoisResult?.registrantOrganization,
        whoisResult?.RegistrantOrganization,
        whoisResult?.registrant?.organization,
        whoisResult?.Registrant?.organization
    );

    const country = firstDefined(
        whoisResult?.registrantCountry,
        whoisResult?.RegistrantCountry,
        whoisResult?.country,
        whoisResult?.registrant?.country,
        whoisResult?.Registrant?.country
    );

    const createdDate = normalizeToIsoDate(
        whoisResult?.creationDate,
        whoisResult?.createdDate,
        whoisResult?.created,
        whoisResult?.registered,
        whoisResult?.domainRegistrationDate,
        whoisResult?.['Creation Date'],
        whoisResult?.['Created On'],
        whoisResult?.['Created'],
        whoisResult?.['Registration Time'],
        whoisResult?.['RegDate'],
        whoisResult?.['Registered'],
        // Indian domains specific
        whoisResult?.['Created On'],
        whoisResult?.['Registered On'],
        extractValueFromRaw(rawText, [
            'Creation Date',
            'Created On',
            'Created',
            'Domain Registration Date',
            'Registered On',
            'RegDate'
        ])
    );

    const expiresDate = normalizeToIsoDate(
        whoisResult?.registrarRegistrationExpirationDate,
        whoisResult?.expiresDate,
        whoisResult?.expirationDate,
        whoisResult?.registryExpiryDate,
        whoisResult?.paidTill,
        whoisResult?.domainExpirationDate,
        whoisResult?.['Registry Expiry Date'],
        whoisResult?.['Registrar Registration Expiration Date'],
        whoisResult?.['Expiry Date'],
        whoisResult?.['Expiration Time'],
        // Indian domains specific
        whoisResult?.['Expiry Date'],
        whoisResult?.['Expires On'],
        extractValueFromRaw(rawText, [
            'Registry Expiry Date',
            'Registrar Registration Expiration Date',
            'Expiration Date',
            'Expiry Date',
            'Expires On'
        ])
    );
    const age = computeAgeYears(createdDate);

    const ipAddress = dnsResult?.address ?? null;
    const ipType = dnsResult?.IPfamily === 4 ? 'IPv4' : dnsResult?.IPfamily === 6 ? 'IPv6' : null;

    // Check if host is an IP address
    const isIP = utils.isValidIPaddress(host);

    // Base response
    const response = {
        domain: host,
        registrant: {
            organization: organization ?? null,
            country: country ?? null
        },
        hosting: {
            ipAddress,
            ipType
        }
    };

    // Add registration details ONLY for domains (not IPs)
    if (!isIP) {
        response.registration = {
            createdDate: createdDate ?? null,
            expiresDate: expiresDate ?? null,
            age: age ?? null
        };
        response.registrar = registrar ?? null;
    }

    return response;
}
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

        // Get WHOIS data with timeout and fallback
        let whoisResult;
        try {
            const whoisPromise = whoisjson(host, { 
                follow: 3, 
                timeout: 15000 
            });
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('WHOIS lookup timeout')), 15000)
            );

            whoisResult = await Promise.race([whoisPromise, timeoutPromise]);
        } catch (whoisError) {
            console.log(`Primary WHOIS lookup failed for ${host}:`, whoisError.message);
            
            // Try with alternative server for .in domains
            if (host.endsWith('.in') || host.endsWith('.ac.in') || host.endsWith('.co.in')) {
                console.log('Attempting fallback WHOIS server for .in domain...');
                try {
                    const fallbackPromise = whoisjson(host, { 
                        server: 'whois.inregistry.net',
                        timeout: 15000 
                    });
                    const timeoutPromise = new Promise((_, reject) => 
                        setTimeout(() => reject(new Error('Fallback WHOIS lookup timeout')), 15000)
                    );
                    
                    whoisResult = await Promise.race([fallbackPromise, timeoutPromise]);
                } catch (fallbackError) {
                    console.log(`Fallback WHOIS lookup also failed:`, fallbackError.message);
                    // Graceful handling ONLY for .in/.ac.in/.co.in domains:
                    // return partial response with DNS data (if available) instead of failing the request.
                    let dnsResult = null;
                    try {
                        dnsResult = await dnsLookupWithTimeout(host, 5000);
                    } catch (dnsError) {
                        console.log(`DNS lookup failed for ${host}:`, dnsError.message);
                    }

                    return res.status(206).json({
                        domain: host,
                        registrant: {
                            organization: null,
                            country: null
                        },
                        hosting: {
                            ipAddress: dnsResult?.address ?? null,
                            ipType: dnsResult?.IPfamily === 4 ? 'IPv4' : dnsResult?.IPfamily === 6 ? 'IPv6' : null
                        },
                        note: "WHOIS data unavailable for this domain. Only DNS information is provided.",
                        whoisError: "WHOIS_SERVER_UNAVAILABLE"
                    });
                }
            } else {
                throw whoisError;
            }
        }

        if (!whoisResult) {
            return res.status(404).json({ 
                msg: "No WHOIS data found for the provided host.",
                error: "NO_DATA"
            });
        }

        // Get DNS information with timeout
        let dnsResult = null;
        try {
            dnsResult = await dnsLookupWithTimeout(host, 5000);
        } catch (dnsError) {
            console.log(`DNS lookup failed for ${host}:`, dnsError.message);
        }

        const simplified = buildSimplifiedWhois({ host, whoisResult, dnsResult });
        res.json(simplified);

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