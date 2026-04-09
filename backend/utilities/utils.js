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
        // if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {
        //     return true;
        // }
        // //regex with subnet
        // if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(3[0-2]|[12]?[0-9]))?$/.test(ipaddress)) {
        //     return true;
        // }
        // return false

        //Best Practice  // 12.23.23.14/32

        let [address, cidr] = ipaddress.split("/");

        // CIDR check
        if (cidr !== undefined) {
            cidr = Number(cidr);
            if (isNaN(cidr) || cidr < 0 || cidr > 32) return false;
        }

        let parts = address.split(".");

        if (parts.length !== 4) return false;

        for (let part of parts) {
            if (!/^\d+$/.test(part)) return false;

            let num = Number(part);

            if (num < 0 || num > 255) return false;

            // leading zero check
            if (part.length > 1 && part.startsWith("0")) return false;
        }

        return true;
    },

    fetchWhois: async function (host) {
        try {
            const result = await whoisjson(host);
            return result;
        } catch (error) {
            return false;
        }
    }
}
