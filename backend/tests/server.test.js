const mongoose = require('mongoose');
const request = require('supertest');
const app = require('../server');

describe('Server and Environment setup tests', () => {
  // Database connection is automatically opened by server.js
  // We need to close it after our tests to prevent Jest from hanging
  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  it('Express App should be defined', () => {
    expect(app).toBeDefined();
  });

  it('Should return 404 for non-existent API routes', async () => {
    const response = await request(app).get('/api/this-route-does-not-exist');
    expect(response.status).toBe(404);
  });

  it('Should not expose x-powered-by header in responses for security', async () => {
    const response = await request(app).get('/api/this-route-does-not-exist');
    // x-powered-by nahi hona chahiye
    expect(response.headers['x-powered-by']).toBeUndefined();
  });
});

describe('Rate limiting test', () => {
  it('Should block login requests after 5 attempts (Brute Force Protection)', async () => {
    //step 1 => sent continue 5 req
    for (let i = 0; i < 5; i++) {
      const response = await request(app).post('/api/auth/login').send({});
      //yha hmain 400 bad req show hoga 
    }
    //step2 => sent 6th req
    const blockedResponse = await request(app).post('/api/auth/login').send({});

    expect(blockedResponse.status).toBe(429);

    expect(blockedResponse.text).toContain('Too many attempts');
  })
});


