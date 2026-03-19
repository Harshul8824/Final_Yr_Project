const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const IPHistory = require('../models/IPHistory');
const { requireAuth } = require('../middleware/auth');

router.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const userId = req.user.userId;
        const objectId = new mongoose.Types.ObjectId(userId);

        // 1. Total Checks and Risk Breakdown
        const riskStats = await IPHistory.aggregate([
            { $match: { userId: objectId } },
            { 
               $group: {
                  _id: "$overallRisk",
                  count: { $sum: 1 }
               }
            }
        ]);

        let totalChecks = 0;
        let riskBreakdown = { High: 0, Medium: 0, Low: 0 };
        
        riskStats.forEach(stat => {
            const r = stat._id || 'Low';
            riskBreakdown[r] = (riskBreakdown[r] || 0) + stat.count;
            totalChecks += stat.count;
        });

        const vpnDetected = riskBreakdown.High + riskBreakdown.Medium;
        const cleanIPs = riskBreakdown.Low;

        // Fetch recent 2000 records to quickly tally threats, timelines, and frequent IPs in JS securely
        // Doing this in NodeJS memory is fine for smaller user-scoped datasets and avoids overly-complex aggregates
        const allHistory = await IPHistory.find({ userId })
                                          .limit(2000)
                                          .select('results overallRisk ip checkedAt')
                                          .sort({ checkedAt: -1 })
                                          .lean();

        let threatCounts = { TOR: 0, VPN: 0, PROXY: 0, Clean: 0 };
        
        // 2. Recent Activity (last 5)
        const recentActivity = allHistory.slice(0, 5).map(h => ({
            ip: h.ip,
            checkedAt: h.checkedAt,
            overallRisk: h.overallRisk || 'Low'
        }));

        // 3. Over time (last 7 days window map)
        const checksOverTimeMap = {};
        for(let i=6; i>=0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            checksOverTimeMap[d.toISOString().split('T')[0]] = 0;
        }

        const ipFrequencies = {};

        allHistory.forEach(h => {
            // Tally specific threats deeply inside JSON tree
            let hasThreat = false;
            
            const isTor = h.results?.onlineDataCheck?.threatType === 'TOR Edge Node' || 
                          h.results?.onlineDataCheck?.threatType?.toUpperCase()?.includes('TOR') || 
                          h.results?.qualityScore?.isTor;
                          
            const isProxy = h.results?.qualityScore?.isProxy || 
                            h.results?.localIPSearch?.result === 1;
                            
            const isVpn = h.overallRisk === 'High' || 
                          h.overallRisk === 'Medium' || 
                          h.results?.qualityScore?.isVPN || 
                          h.results?.vpnListCheck?.result === 1;

            if (isTor) {
                threatCounts.TOR++;
                hasThreat = true;
            } else if (isProxy) {
               threatCounts.PROXY++;
               hasThreat = true;
            } else if (isVpn) {
               threatCounts.VPN++;
               hasThreat = true;
            }
            
            if (!hasThreat) {
                threatCounts.Clean++;
            }

            // Tally dates for time-series chart
            if (h.checkedAt) {
                const dateStr = new Date(h.checkedAt).toISOString().split('T')[0];
                if (checksOverTimeMap[dateStr] !== undefined) {
                    checksOverTimeMap[dateStr]++;
                }
            }

            // Frequency tally for Top Risky IPs
            if (h.overallRisk === 'High' || h.overallRisk === 'Medium') {
                if (!ipFrequencies[h.ip]) {
                    ipFrequencies[h.ip] = { count: 0, risk: h.overallRisk };
                }
                ipFrequencies[h.ip].count++;
            }
        });

        // 4. Format outputs for UI
        const threatTypesArray = [
            { type: "TOR", count: threatCounts.TOR },
            { type: "VPN", count: threatCounts.VPN },
            { type: "PROXY", count: threatCounts.PROXY },
            { type: "Clean", count: threatCounts.Clean }
        ];

        const checksOverTimeArray = Object.keys(checksOverTimeMap).map(date => ({
            date,
            count: checksOverTimeMap[date]
        }));

        const topRiskyIPsArray = Object.keys(ipFrequencies).map(ip => ({
            ip,
            count: ipFrequencies[ip].count,
            risk: ipFrequencies[ip].risk
        })).sort((a,b) => b.count - a.count).slice(0, 5);

        // Optional standard route fallback
        if(req.path === '/getallanalytics') return res.status(200).json({});

        res.status(200).json({
            totalChecks,
            vpnDetected,
            cleanIPs,
            riskBreakdown: {
                high: riskBreakdown.High,
                medium: riskBreakdown.Medium,
                low: riskBreakdown.Low
            },
            threatTypes: threatTypesArray,
            recentActivity,
            checksOverTime: checksOverTimeArray,
            topRiskyIPs: topRiskyIPsArray
        });

    } catch (err) {
        console.error('Analytics dashboard error:', err);
        res.status(500).json({ msg: "Server error", error: err.message });
    }
});

module.exports = router;