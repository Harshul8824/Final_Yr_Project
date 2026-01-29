const whoisjson = require('whois-json');
const axios = require('axios');
module.exports = {
    /**
     * 
     * @param {String} url 
     */
    extractHostname: function (url) {
        var hostname;
        
        // Find & remove protocol (http, ftp, etc.) and get hostname
        if (url.indexOf("//") > -1) {
            hostname = url.split('/')[2];
        }
        else {
            hostname = url.split('/')[0];
        }
        
        // Find & remove port number
        hostname = hostname.split(':')[0];
        
        // Find & remove "?"
        hostname = hostname.split('?')[0];
        
        // Return full hostname (DO NOT remove subdomains)
        // Multi-level TLDs like .ac.in, .co.uk, .co.in need complete domain
        return hostname;
    },
    isValidIPaddress: function (ipaddress) {
        //Normal reged
        if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {
            return true;
        }
        //regex with subnet
        if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/\d{1,2})?$/.test(ipaddress)) {
            return true;
        }
        return false
    },

    fetchWhois: async function (host) {
        try {
            const result = await whoisjson(host);
            return result;
        } catch (error) {
            return false;
        }
    },
    // ML functions removed - using MERN stack only
}
    