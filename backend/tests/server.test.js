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
});
