const mongoose = require('mongoose');
const dayjs = require('dayjs');
const Token = require('../models/token.model');
const TokenService = require('../src/index');
const jwt = require('jsonwebtoken');

const tokenTypes = { ACCESS: 'access', REFRESH: 'refresh' };
const config = {
  secret: 'your_jwt_secret',
  jwt: { accessExpirationMinutes: 15, refreshExpirationDays: 30 }
};

// --- UNIT TESTS WITH MOCK ---
describe('TokenService (unit, mock model)', () => {
  const tokens = [];
  const MockToken = {
    create: jest.fn(async (doc) => {
      tokens.push(doc);
      return doc;
    }),
    findOne: jest.fn(async (query) => {
      return tokens.find(
        t => t.token === query.token &&
             t.type === query.type &&
             t.user === query.user &&
             t.blacklisted === query.blacklisted
      ) || null;
    })
  };
  const service = new TokenService(MockToken, tokenTypes, config);
  const userId = 'user123';

  beforeEach(() => { tokens.length = 0; });

  test('should generate and verify access token', async () => {
    const tokensObj = await service.generateAuthTokens(userId);
    expect(tokensObj.access.token).toBeDefined();
    const payload = jwt.verify(tokensObj.access.token, config.secret);
    expect(payload.sub).toBe(userId);
    expect(payload.type).toBe(tokenTypes.ACCESS);
  });

  test('should save and verify refresh token', async () => {
    const tokensObj = await service.generateAuthTokens(userId);
    const tokenDoc = await service.verifyToken(tokensObj.refresh.token, tokenTypes.REFRESH);
    expect(tokenDoc.token).toBe(tokensObj.refresh.token);
    expect(tokenDoc.user).toBe(userId);
    expect(tokenDoc.type).toBe(tokenTypes.REFRESH);
    expect(tokenDoc.blacklisted).toBe(false);
  });

  test('should throw error for invalid token', async () => {
    await expect(service.verifyToken('invalid.token.here', tokenTypes.ACCESS)).rejects.toThrow('Token invalid or expired');
  });

  test('should throw error if token not found in db', async () => {
    const token = service.generateToken(userId, dayjs().add(1, 'hour'), tokenTypes.ACCESS);
    await expect(service.verifyToken(token, tokenTypes.ACCESS)).rejects.toThrow('Token not found');
  });
});

// --- INTEGRATION TEST WITH REAL MONGOOSE MODEL ---
describe('TokenService (integration, real model)', () => {
  const userId = new mongoose.Types.ObjectId();
  const service = new TokenService(Token, tokenTypes, config);

  beforeAll(async () => {
    await mongoose.connect('mongodb://localhost:27017/tokenservicetest');
  });

  afterAll(async () => {
    await mongoose.connection.db.dropDatabase();
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    await Token.deleteMany({});
  });

  test('should generate and save tokens', async () => {
    const tokensObj = await service.generateAuthTokens(userId);
    expect(tokensObj).toHaveProperty('access.token');
    expect(tokensObj).toHaveProperty('refresh.token');
    // Check DB for saved refresh token
    const saved = await Token.findOne({ token: tokensObj.refresh.token });
    expect(saved).not.toBeNull();
    expect(saved.user.toString()).toBe(userId.toString());
    expect(saved.type).toBe(tokenTypes.REFRESH);
    expect(saved.blacklisted).toBe(false);
  });
});
