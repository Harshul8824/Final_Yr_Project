const vpnCheck = require('../utilities/vpnCheck')
const router = require('express').Router();
const nmap = require('libnmap');
const path = require('path');
const { spawn, exec, execFile } = require('child_process');
const axios = require('axios');
var ip2proxy = require("ip2proxy-nodejs");
const whoisjson = require('whois-json');
const fs = require('fs');
const utils = require('../utilities/utils');

// Optional file paths for VPN/IP lists (create these files or set env vars to enable)
const vpnIps = process.env.VPN_IPS_PATH || path.join(__dirname, '..', 'MLServerCode', 'scripts', 'IPv4_VPNs.txt');
const listOfIps = process.env.LIST_OF_IPS_PATH || path.join(__dirname, '..', 'MLServerCode', 'scripts', 'ips.txt');
const ip2proxyDbPath = process.env.IP2PROXY_DATABASE_PATH || path.join(__dirname, '..', 'data', 'PX11-Lite.BIN');

// Tor exit node list (public, no API key) — cache for 10 minutes
const TOR_EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
let torExitListCache = { ips: null, fetchedAt: 0 };
const TOR_CACHE_TTL_MS = 10 * 60 * 1000;

/** Check if IP appears as an exact line in file (avoids indexOf false positives like 185.220.101.1 matching 185.220.101.10) */
function ipInFileLines(filePath, ip) {
    try {
        const data = fs.readFileSync(filePath, 'utf-8');
        const lines = data.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        return lines.includes(ip);
    } catch (e) {
        return false;
    }
}

/** Resolve host to IP (returns host if already valid IP) */
async function resolveToIp(host) {
    const h = (host && typeof host === 'string') ? host.trim() : '';
    if (!h) return null;
    if (utils.isValidIPaddress(h)) return h;
    try {
        const dns = require('dns');
        const { promisify } = require('util');
        const lookup = promisify(dns.lookup);
        const resolved = await lookup(h, { family: 4 });
        return resolved.address;
    } catch (e) {
        return null;
    }
}

async function getTorExitIps() {
    if (torExitListCache.ips && (Date.now() - torExitListCache.fetchedAt) < TOR_CACHE_TTL_MS) {
        return torExitListCache.ips;
    }
    try {
        const res = await axios.get(TOR_EXIT_LIST_URL, { timeout: 15000, responseType: 'text' });
        const text = Buffer.isBuffer(res.data) ? res.data.toString('utf8') : (typeof res.data === 'string' ? res.data : String(res.data));
        const lines = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        const ips = new Set(lines);
        torExitListCache = { ips, fetchedAt: Date.now() };
        return ips;
    } catch (e) {
        if (torExitListCache.ips) return torExitListCache.ips;
        return new Set();
    }
}



    /**vpn port scan
     * 
     * @param {String} url 
     */

router.route('/vpnports').post(async (req, res) => {
    // Set response timeout
    res.setTimeout(60000, () => {
        if (!res.headersSent) {
            res.status(408).json({ 
                msg: "Port scan timeout. The scan is taking too long.", 
                error: "TIMEOUT" 
            });
        }
    });

    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name or IP address" });
        }

        // Extract hostname if it's a URL
        if (!utils.isValidIPaddress(host)) {
            host = utils.extractHostname(host);
            if (!host) {
                return res.status(400).json({ msg: "Could not extract valid hostname from input." });
            }
        }

        // Scanning options for VPN ports
        const opts = {
            json: true,
            range: [host],
            ports: '1723,1701,500,4500,1194,443',
            verbose: true,
        };

        // Wrap nmap.scan in a Promise for better error handling
        const scanPromise = new Promise((resolve, reject) => {
            nmap.scan(opts, function (err, report) {
                if (err) {
                    return reject(err);
                }
                resolve(report);
            });
        });

        // Add timeout to the scan
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Port scan timeout')), 55000)
        );

        const report = await Promise.race([scanPromise, timeoutPromise]);

        if (!report || Object.keys(report).length === 0) {
            return res.status(404).json({ 
                status: "Host is down", 
                msg: "No scan results available", 
                ports: [] 
            });
        }

        // Parse nmap report structure safely
        let hostUp = false;
        let openPorts = [];
        let hostname = null;

        for (let item in report) {
            try {
                const scanItem = report[item];
                
                // Check if host is up
                const runstats = scanItem?.runstats?.[0];
                const hosts = runstats?.hosts?.[0];
                const hostStatus = hosts?.item?.up;
                
                if (hostStatus === "1" || hostStatus === 1) {
                    hostUp = true;

                    // Extract host information
                    const hostData = scanItem?.host?.[0];
                    if (hostData) {
                        // Extract hostname
                        const hostnames = hostData?.hostnames?.[0];
                        if (hostnames?.hostname) {
                            hostname = hostnames.hostname;
                        }

                        // Extract open ports
                        const ports = hostData?.ports?.[0];
                        if (ports && ports.port) {
                            // Helper function to safely extract port number
                            const extractPortNumber = (p) => {
                                if (typeof p === 'number' || typeof p === 'string') {
                                    return String(p);
                                }
                                if (p?.item?.portid) return String(p.item.portid);
                                if (p?.item?.port) return String(p.item.port);
                                if (p?.portid) return String(p.portid);
                                if (p?.port && (typeof p.port === 'number' || typeof p.port === 'string')) {
                                    return String(p.port);
                                }
                                return null;
                            };

                            // Helper function to safely extract protocol
                            const extractProtocol = (p) => {
                                if (typeof p === 'string') return p;
                                return p?.item?.protocol || p?.protocol || 'tcp';
                            };

                            // Helper function to safely extract state - RETURNS STRING
                            const extractState = (p) => {
                                const stateData = p?.state;
                                
                                // If it's already a string
                                if (typeof stateData === 'string') return stateData;
                                
                                // If it's an array (common nmap format)
                                if (Array.isArray(stateData)) {
                                    const stateObj = stateData[0];
                                    if (stateObj?.item?.state) return stateObj.item.state;
                                    if (stateObj?.state) return stateObj.state;
                                    return 'unknown';
                                }
                                
                                // If it's an object
                                if (stateData && typeof stateData === 'object') {
                                    if (stateData.item?.state) return stateData.item.state;
                                    if (stateData.state) return stateData.state;
                                }
                                
                                // Fallback
                                return p?.item?.state || 'open';
                            };

                            // Helper function to safely extract service
                            const extractService = (p) => {
                                return p?.item?.service?.name || p?.service?.name || null;
                            };

                            // ports.port can be an array or single object
                            if (Array.isArray(ports.port)) {
                                openPorts = ports.port.map(p => {
                                    const portNum = extractPortNumber(p);
                                    if (!portNum) return null;
                                    return {
                                        port: portNum,
                                        protocol: extractProtocol(p),
                                        state: extractState(p),  // Now returns string
                                        service: extractService(p)
                                    };
                                }).filter(p => p !== null);
                            } else if (ports.port.item) {
                                // Single port object
                                const portNum = extractPortNumber(ports.port);
                                if (portNum) {
                                    openPorts = [{
                                        port: portNum,
                                        protocol: extractProtocol(ports.port),
                                        state: extractState(ports.port),  // Now returns string
                                        service: extractService(ports.port)
                                    }];
                                }
                            } else {
                                // Direct port value
                                const portNum = extractPortNumber(ports.port);
                                if (portNum) {
                                    openPorts = [{
                                        port: portNum,
                                        protocol: extractProtocol(ports.port),
                                        state: extractState(ports.port),  // Now returns string
                                        service: extractService(ports.port)
                                    }];
                                }
                            }
                        }
                    }
                    break; // Process first host result
                }
            } catch (parseError) {
                console.log(`Error parsing scan item ${item}:`, parseError.message);
                continue;
            }
        }

        // Count only truly OPEN ports (now state is a string)
        const trulyOpenPorts = openPorts.filter(p => {
            return p.state === 'open';
        });

        // Build response
        const response = {
            status: hostUp ? "Host is Up" : "Host is down",
            ports: openPorts,
            hostname: hostname || host,
            scannedHost: host,
            openPortsCount: trulyOpenPorts.length
        };

        if (!hostUp) {
            response.msg = "Host is down or not responding to port scan";
        }

        res.json(response);

    } catch (error) {
        console.error('VPN Port Scan Error:', error);
        
        if (error.message.includes('timeout')) {
            res.status(408).json({ 
                msg: "Port scan timeout. The host might be unreachable or firewall is blocking.",
                error: "TIMEOUT",
                status: "Timeout",
                ports: []
            });
        } else {
            res.status(500).json({ 
                msg: "Port scan failed. Please ensure nmap is installed and the host is reachable.",
                error: "SCAN_FAILED",
                status: "Error",
                ports: [],
                details: error.message
            });
        }
    }
});


/**ML running for ip cidr
 * 
 * @param {String} hostipaddr 
 */
router.route('/checkcidr').post(async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name of ip addresss" });
        }


        var dataToSend;
        // spawn new child process to call the python script
        const pythonExec = exec(`python ./scripts/checkIp.py ${host}`, { cwd: "./MLServerCode/" }, function (err, stdout, stderr) {
            if (stdout) {
                dataToSend = stdout;
                dataToSend = dataToSend == 'true' ? 1 : 0;
                res.json({ result: dataToSend });
                return;
            }
            else if (err) {
                res.status(500).json({ msg: "Some error occured. Please try again later", err: err.message });
                return;
            }
            else {
                res.status(500).json({ msg: "Some error occured. Please try again later", err: "" });

            }
        });
        // collect data from script
        // python.stdout.on('data', function (data) {
        //     console.log('Pipe data from python script ...');
        //     dataToSend = data.toString();
        // });
        // // in close event we are sure that stream from child process is closed
        // python.on('close', (code) => {
        //     console.log(`child process close all stdio with code ${code}`);
        //     // send data to browser
        //     res.json({ checkIp: dataToSend })
        // });



    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
    }

});

/** Quality Score — IPQualityScore API when key set, else local checks (Tor + VPN list + online list + IP2Proxy)
 * @param {string} host
 */
router.route('/qualityscore').post(async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name or IP address" });
        }
        host = host.trim();

        const ip = await resolveToIp(host);
        if (!ip) {
            return res.status(400).json({ msg: "Could not resolve hostname to IP.", err: "RESOLVE_FAILED" });
        }

        const apiKey = (process.env.IP_QUALITY_SCORE_API_KEY || '').trim().replace(/[;\s]+$/, '');

        // If API key is set, use IPQualityScore API
        if (apiKey) {
            try {
                const url = `https://www.ipqualityscore.com/api/json/ip/${encodeURIComponent(apiKey)}/${encodeURIComponent(ip)}`;
                const response = await axios.get(url, { timeout: 12000 });
                const data = response.data;

                if (data && data.success !== false) {
                    return res.json({
                        result: {
                            proxy: !!data.proxy,
                            vpn: !!data.vpn,
                            tor: !!data.tor,
                            torExit: !!data.tor,
                            fraud_score: data.fraud_score != null ? data.fraud_score : 0,
                            success: true,
                            source: "ipqualityscore"
                        },
                        note: "Result from IPQualityScore API."
                    });
                }
            } catch (apiErr) {
                if (apiErr.response && apiErr.response.status === 401) {
                    return res.status(500).json({ msg: "Invalid IPQualityScore API key. Check IP_QUALITY_SCORE_API_KEY in .env", err: "API_KEY_INVALID" });
                }
                if (apiErr.code === 'ECONNABORTED' || apiErr.code === 'ETIMEDOUT') {
                    return res.status(504).json({ msg: "IPQualityScore API timeout. Try again later.", err: "TIMEOUT" });
                }
                return res.status(500).json({ msg: "IPQualityScore API failed.", err: apiErr.message || String(apiErr) });
            }
        }

        // No API key — use local checks
        let vpnListHit = false;
        let onlineListHit = false;
        let localProxyHit = false;
        let torExitHit = false;

        if (fs.existsSync(vpnIps)) {
            vpnListHit = ipInFileLines(vpnIps, ip);
        }
        if (fs.existsSync(listOfIps)) {
            onlineListHit = ipInFileLines(listOfIps, ip);
        }
        try {
            const torIps = await getTorExitIps();
            torExitHit = torIps.has(ip);
        } catch (e) { /* ignore */ }
        if (fs.existsSync(ip2proxyDbPath)) {
            try {
                ip2proxy.Open(ip2proxyDbPath);
                const val = ip2proxy.isProxy(ip);
                localProxyHit = (val === 1 || val === 2 || val === true);
            } catch (e) { /* ignore */ }
        }

        const anyHit = vpnListHit || onlineListHit || localProxyHit || torExitHit;
        const fraud_score = anyHit ? 100 : 0;

        res.json({
            result: {
                proxy: localProxyHit,
                vpn: vpnListHit || onlineListHit || torExitHit,
                torExit: torExitHit,
                fraud_score,
                success: true,
                source: "local"
            },
            note: "No API key set. Result from local checks (VPN list, online list, Tor, proxy DB). Set IP_QUALITY_SCORE_API_KEY in .env for API."
        });
    } catch (error) {
        res.status(500).json({ msg: "Quality Score check failed.", err: error.message || String(error) });
    }
});

// ML intel score route removed - using MERN stack only

//local search

/** Local IP Search — IP2Proxy DB if configured, else Tor exit list (no API key)
 * @param {string} host
 */
router.route('/ipsearch').post(async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name or IP address" });
        }
        host = host.trim();

        const ip = await resolveToIp(host);
        if (!ip) {
            return res.json({ result: 0, note: "Could not resolve hostname to IP." });
        }

        // If IP2Proxy DB exists, use it (0=not proxy, 1=proxy, 2=datacenter)
        if (fs.existsSync(ip2proxyDbPath)) {
            try {
                ip2proxy.Open(ip2proxyDbPath);
                const val = ip2proxy.isProxy(ip);
                const found = (val === 1 || val === 2 || val === true);
                const result = found ? 1 : 0;
                return res.json({
                    result,
                    note: found ? "IP found in proxy/VPN database (IP2Proxy)." : "IP not in proxy database."
                });
            } catch (openErr) {
                return res.json({ result: 0, note: "Could not open IP2Proxy database. Check file path and format." });
            }
        }

        // Fallback: check Tor exit list (so Local IP Search still works without DB)
        try {
            const torIps = await getTorExitIps();
            const found = torIps.has(ip);
            const result = found ? 1 : 0;
            return res.json({
                result,
                note: found ? "IP found in Tor exit list (proxy DB not configured)." : "Checked Tor list only (proxy DB not configured)."
            });
        } catch (e) {
            return res.json({ result: 0, note: "Local proxy DB not configured. Set IP2PROXY_DATABASE_PATH or add PX11-Lite.BIN to backend/data/." });
        }
    } catch (error) {
        res.status(500).json({ msg: "Local IP search failed.", err: error.message });
    }
});

/**check(ml) running for organisation
 * 
 * @param {String} hostipaddr 
 */
router.route('/checkorg').post(async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name of ip addresss" });
        }
        // if (!utils.isValidIPaddress(host)) {
        //     host = utils.extractHostname(host);
        //     // res.json(host)
        //     console.log(host);
        // }
        const result = await whoisjson(host);
        const stringResult = `{"orgName":"${result.orgName}"}`

        // res.json(stringResult);

        var dataToSend;
        // spawn new child process to call the python script
        const pythonExec = exec(`python ./scripts/checkOrg.py << ${stringResult}`, { cwd: "./MLServerCode/" }, function (err, stdout, stderr) {
            if (stdout) {
                dataToSend = stdout;
                dataToSend = dataToSend == 'true' ? 1 : 0;
                res.json({ result: dataToSend });
                return;
            }
            else if (err) {
                res.status(500).json({ msg: "Some error occured. Please try again later", err: err.message });
                return;
            }
            else {
                res.status(500).json({ msg: "Some error occured. Please try again later", err: "" });

            }
        });
        // collect data from script
        // python.stdout.on('data', function (data) {
        //     console.log('Pipe data from python script ...');
        //     dataToSend = data.toString();
        // });
        // // in close event we are sure that stream from child process is closed
        // python.on('close', (code) => {
        //     console.log(`child process close all stdio with code ${code}`);
        //     // send data to browser
        //     res.json({ checkIp: dataToSend })
        // });



    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
    }

});
router.post('/checkip', async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name or IP address" });
        }
        host = host.trim();

        const ip = await resolveToIp(host);
        if (!ip) {
            return res.status(400).json({ msg: "Could not resolve hostname to IP." });
        }

        // If VPN list file exists, check with exact line match (no substring false positives)
        if (fs.existsSync(vpnIps)) {
            const found = ipInFileLines(vpnIps, ip);
            const result = found ? 1 : 0;
            return res.json({
                result,
                note: found ? "IP found in VPN list (IPv4_VPNs.txt)." : "IP not in VPN list."
            });
        }

        // Fallback: check Tor exit list (so VPN List Check still works without file)
        try {
            const torIps = await getTorExitIps();
            const found = torIps.has(ip);
            const result = found ? 1 : 0;
            return res.json({
                result,
                note: found ? "IP found in Tor exit list (VPN list file not configured)." : "Checked Tor list only (VPN list file not configured)."
            });
        } catch (e) {
            return res.json({ result: 0, note: "VPN list file not configured. Add IPv4_VPNs.txt to backend/MLServerCode/scripts/ to enable." });
        }
    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
    }
});

router.post('/checkonlinedata', async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name or IP address" });
        }
        host = host.trim();

        const ip = await resolveToIp(host);
        if (!ip) {
            return res.json({ result: 0, note: "Could not resolve hostname to IP." });
        }

        // If local list file exists, use exact line match (no substring false positives)
        if (fs.existsSync(listOfIps)) {
            const found = ipInFileLines(listOfIps, ip);
            const result = found ? 1 : 0;
            return res.json({
                result,
                note: found ? "IP found in online threat list (ips.txt)." : "IP not in online list."
            });
        }

        // Else check against Tor exit node list (public, no API key)
        try {
            const torIps = await getTorExitIps();
            const found = torIps.has(ip);
            const result = found ? 1 : 0;
            return res.json({
                result,
                note: found ? "IP found in Tor exit node list (high risk)." : "Checked Tor exit list; IP not in list."
            });
        } catch (e) {
            return res.json({ result: 0, note: "Online list file not configured and Tor list unavailable. Add ips.txt to backend/MLServerCode/scripts/ or retry later." });
        }
    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
    }
});


router.route('/getrealip').post(function (req, res) {
    try {
        // need access to IP address here
        var ip = (req.headers['x-forwarded-for'] || '').split(',').pop().trim() || 
             req.connection.remoteAddress || 
             req.socket.remoteAddress || 
             req.connection.socket.remoteAddress
        console.log(ip,req.headers);
        res.json({ ip: ip });
    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
    }
})

module.exports = router;