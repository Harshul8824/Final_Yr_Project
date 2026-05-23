const router = require('express').Router();
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, //1 hr
  max: 5,  //send max 5 req
  message: 'Too many attempts, please try again after 1 hour'
});


function signToken(user) {
  const secret = process.env.JWT_SECRET;
  return jwt.sign(
    { userId: user._id.toString(), role: user.role, email: user.email },
    secret,
    { expiresIn: '7d' }
  );
}

router.post('/register', authLimiter, async (req, res) => {
  try {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!name || !email || !password) {
      return res.status(400).json({ msg: 'Name, email and password are required.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ msg: 'Password must be at least 6 characters.' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ msg: 'Email already registered.' });
    }

    const passwordHash = await User.hashPassword(password);
    const user = await User.create({ name, email, passwordHash });
    const token = signToken(user);

    return res.status(201).json({ token, user: user.toSafeJSON() });
  } catch (e) {
    // Handle unique constraint race condition
    if (e?.code === 11000) {
      return res.status(409).json({ msg: 'Email already registered.' });
    }
    return res.status(500).json({ msg: 'Registration failed.', error: e.message });
  }
});

router.post('/login', authLimiter, async (req, res) => {
  console.log(req.query);
  try {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!email || !password) {
      return res.status(400).json({ msg: 'Email and password are required.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ msg: 'Invalid credentials.' });
    }

    const ok = await User.verifyPassword(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ msg: 'Invalid credentials.' });
    }

    const token = signToken(user);
    return res.json({ token, user: user.toSafeJSON() });
  } catch (e) {
    return res.status(500).json({ msg: 'Login failed.', error: e.message });
  }
});

router.get('/me', requireAuth, async (req, res) => {
  try {
    const userId = req.user?.userId;
    const user = await User.findById(userId);
    if (!user) return res.status(401).json({ msg: 'Unauthorized', error: 'USER_NOT_FOUND' });
    return res.json({ user: user.toSafeJSON() });
  } catch (e) {
    return res.status(500).json({ msg: 'Failed to load user.', error: e.message });
  }
});

module.exports = router;

