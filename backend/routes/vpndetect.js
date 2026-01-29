const vpnCheck = require('../utilities/vpnCheck')
const router = require('express').Router();
const nmap = require('libnmap');
const { spawn, exec, execFile } = require('child_process');
const axios = require('axios');
var ip2proxy = require("ip2proxy-nodejs");
const whoisjson = require('whois-json');
const fs = require('fs');
const utils = require('../utilities/utils');



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

                            // Helper function to safely extract state
                            const extractState = (p) => {
                                return p?.item?.state || p?.state || 'open';
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
                                        state: extractState(p),
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
                                        state: extractState(ports.port),
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
                                        state: extractState(ports.port),
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

        // Count only truly OPEN ports (not filtered or closed)
const trulyOpenPorts = openPorts.filter(p => {
    // Extract state - handle both array and direct object formats
    let state;
    if (Array.isArray(p.state)) {
        state = p.state[0]?.item?.state || p.state[0];
    } else if (typeof p.state === 'object' && p.state !== null) {
        state = p.state.item?.state || p.state;
    } else {
        state = p.state;
    }
    return state === 'open';
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

/**  gives ip type & fraud score
*
* @param {string} host
*/
router.route('/qualityscore').post(async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name of ip addresss" });
        }
        
        // let key = mcfLlGm2jceQIvqZpc4hmKzkLuuUHtK8;
        
        MLModel2Check(host).then(response=>{
                // console.log(response.data);
                res.json({ result: response.data });
            })
            .catch(error=>{res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });})

    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
    }

});

// ML intel score route removed - using MERN stack only

//local search

// ip2proxy.Open("../data/large.BIN"); // Commented out - database file path needs to be configured
/**  local search
*
* @param {string} host
*/
router.route('/ipsearch').post(async (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name of ip addresss" });
        }
        
        isProxy = ip2proxy.isProxy(host)
        // let key = mcfLlGm2jceQIvqZpc4hmKzkLuuUHtK8;
        console.log("isProxy: " + ip2proxy.isProxy(host));
        console.log("GetModuleVersion: " + ip2proxy.getModuleVersion());
        console.log("GetPackageVersion: " + ip2proxy.getPackageVersion());
        console.log("GetDatabaseVersion: " + ip2proxy.getDatabaseVersion());
        res.json({result:isProxy});

    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });
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
router.post('/checkip', (req, res) => {
    try {
        let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
        if (!host) {
            return res.status(400).json({ msg: "Please provide a host name of ip addresss" });
        }
        const data = fs.readFileSync(vpnIps, 'utf-8');
        let result = data.indexOf(host) > -1 ? 1 : 0;
        res.json({ result: result });

    } catch (error) {
        res.status(500).json({ msg: "Some error occured. Please try again later", err: error.message });

    }
});
router.post('/checkonlinedata', (req, res) => {
    let host = req.body && typeof req.body.host === 'string' ? req.body.host : "";
    if (!host) {
        return res.status(400).json({ msg: "Please provide a host name of ip addresss" });
    }
    const data = fs.readFileSync(listOfIps, 'utf-8');
    let result = data.indexOf(host) > -1 ? 1:0;
    res.json({result:result});
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
