# 🛡️ token-service

A robust, reusable Node.js service for generating, verifying, and managing authentication tokens such as JWT, with MongoDB persistence. Easily plug it into any backend application to handle secure, token-based authentication.

---

## ✨ Features

- JWT access and refresh token generation
- Token verification and blacklisting
- MongoDB token persistence (Mongoose model)
- Configurable expiration and secrets
- Written in modern JavaScript
- Built-in test examples

---

## 🚀 Getting Started

### 1. Install

```bash
npm install token-service
```

or if you're using it locally:

```bash
git clone git@github.com:jossieT/token-service.git
cd token-service
npm install
```

### 2. Usage Example

```js
const TokenService = require('token-service');
const mongoose = require('mongoose');
const dayjs = require('dayjs');

// Example Mongoose Token model and tokenTypes enum
const Token = mongoose.model('Token', new mongoose.Schema({
  token: String,
  user: mongoose.Schema.Types.ObjectId,
  expires: Date,
  type: String,
  blacklisted: Boolean,
}));
const tokenTypes = { ACCESS: 'access', REFRESH: 'refresh' };
const config = {
  secret: 'your_jwt_secret',
  jwt: { accessExpirationMinutes: 15, refreshExpirationDays: 7 }
};

const tokenService = new TokenService(Token, tokenTypes, config);

// Usage inside an async function:
async function main() {
  const userId = new mongoose.Types.ObjectId(); // Example userId
  const tokens = await tokenService.generateAuthTokens(userId);
  console.log(tokens);

  try {
    const tokenDoc = await tokenService.verifyToken(tokens.access.token, tokenTypes.ACCESS);
    console.log('Token is valid:', tokenDoc);
  } catch (err) {
    console.error('Invalid or expired token');
  }
}
main();
```

---

## API

### `generateToken(userId, expires, type, secret)`
- **userId** (`string|ObjectId`): User identifier
- **expires** (`dayjs` object): Expiration time
- **type** (`string`): Token type (e.g., 'access', 'refresh')
- **secret** (`string`, optional): Secret key (defaults to config.secret)
- **Returns:** `string` (JWT token)

### `saveToken(token, userId, expires, type, blacklisted)`
- **token** (`string`): JWT token
- **userId** (`string|ObjectId`): User identifier
- **expires** (`dayjs` object): Expiration time
- **type** (`string`): Token type
- **blacklisted** (`boolean`, optional): Blacklist status (default: false)
- **Returns:** `Promise<Object>` (Token document)

### `verifyToken(token, type)`
- **token** (`string`): JWT token
- **type** (`string`): Token type
- **Returns:** `Promise<Object>` (Token document if valid)
- **Throws:** Error if token is invalid, expired, or not found

### `generateAuthTokens(userId)`
- **userId** (`string|ObjectId`): User identifier
- **Returns:** `Promise<{ access: { token, expires }, refresh: { token, expires } }>`

---

## 🧪 Run Tests

```bash
npm test
```

## 🤝 Contributing

Contributions are welcome! Please open issues or submit a pull request.

## 📄 License

MIT © 2025 Yosef Teshome

