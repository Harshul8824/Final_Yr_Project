const express = require('express');
const router = express.Router();
const IPHistory = require('../models/IPHistory');
const { requireAuth } = require('../middleware/auth');

// POST /api/history/save -> Save IP check result to DB
router.post('/save', requireAuth, async (req, res) => {
  try {
    const { ip, results, overallRisk } = req.body;
    
    // Create new history document mapped strictly to schema
    const newHistory = new IPHistory({
      userId: req.user.userId,
      userEmail: req.user.email,
      ip,
      results,
      overallRisk
    });

    await newHistory.save();
    return res.status(201).json({ msg: 'History saved successfully', history: newHistory });

  } catch (err) {
    console.error('Error saving IP history:', err);
    return res.status(500).json({ msg: 'Server error saving history', error: err.message });
  }
});

// GET /api/history/myhistory -> Get sorted latest history for logged in user (max 50)
router.get('/myhistory', requireAuth, async (req, res) => {
  try {
    const history = await IPHistory.find({ userId: req.user.userId })
                                   .sort({ checkedAt: -1 }) // Sorted by date (latest first)
                                   .limit(50);              // Limit 50 records

    return res.status(200).json(history);
  } catch (err) {
    console.error('Error fetching IP history:', err);
    return res.status(500).json({ msg: 'Server error fetching history', error: err.message });
  }
});

// DELETE /api/history/clear -> Clear user's all history
router.delete('/clear', requireAuth, async (req, res) => {
  try {
    const result = await IPHistory.deleteMany({ userId: req.user.userId });
    return res.status(200).json({ msg: 'History cleared successfully', deletedCount: result.deletedCount });
  } catch (err) {
    console.error('Error clearing IP history:', err);
    return res.status(500).json({ msg: 'Server error clearing history', error: err.message });
  }
});

module.exports = router;
