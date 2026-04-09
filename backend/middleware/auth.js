const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ msg: 'Unauthorized', error: 'NO_TOKEN' });
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return res.status(500).json({ msg: 'Server misconfigured', error: 'JWT_SECRET_MISSING' });
    }

    const payload = jwt.verify(token, secret);
    req.user = payload;
    // console.log(payload);
    return next();
  } catch (e) {
    return res.status(401).json({ msg: 'Unauthorized', error: 'INVALID_TOKEN' });
  }
}

module.exports = { requireAuth };

