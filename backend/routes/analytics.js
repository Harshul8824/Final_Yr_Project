const router = require('express').Router();

router.get('/getallanalytics', async (req, res) => {
    try {
        // MERN stack analytics - no ML data
        const result = {
            totalData: 0,
            trainData: 0,
            testData: 0,
            generateDataLogs: "ML functionality removed - using MERN stack only",
            mlLogs: "ML functionality removed - using MERN stack only",
            systemStatus: "MERN Stack VPN Detection System",
            features: [
                "WHOIS Lookup",
                "VPN Port Scanning", 
                "IP Quality Score",
                "CIDR Range Checking",
                "Batch Processing",
                "Network Scanning"
            ]
        };
        res.json(result);

    } catch (error) {
        res.status(500).json({ msg: "Could not read analytics", err: error.message });
    }

});
module.exports = router;