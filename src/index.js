const jwt = require('jsonwebtoken');
const dayjs = require('dayjs');

/**
 * TokenService handles JWT creation, verification, and persistence.
 * @class
 */
class TokenService {
    /**
     * @param {Object} Token - Mongoose model for token persistence
     * @param {Object} tokenTypes - Enum for token types
     * @param {Object} config - Configuration object (must include secret and jwt settings)
     */
    constructor(Token, tokenTypes, config) {
        if (!Token || !tokenTypes || !config ) {
            throw new Error('TokenService: Missing required constructor parameters.');
        }
        this.Token = Token;
        this.tokenTypes = tokenTypes;
        this.config = config;
    }

    /**
     * Generates a JWT token.
     * @param {string} userId - User ID
     * @param {Object} expires - dayjs object for expiration
     * @param {string} type - Token type
     * @param {string} [secret] - Secret key
     * @returns {string} JWT token
     */
    generateToken(userId, expires, type, secret = this.config.secret) {
        const payload = {
            sub: userId,
            iat: dayjs().unix(),
            exp: expires.unix(),
            type,
        };
        return jwt.sign(payload, secret);
    }

    /**
     * Saves a token document to the database.
     * @param {string} token - JWT token
     * @param {string} userId - User ID
     * @param {Object} expires - dayjs object for expiration
     * @param {string} type - Token type
     * @param {boolean} [blacklisted=false] - Blacklist status
     * @returns {Promise<Object>} Token document
     */
    async saveToken(token, userId, expires, type, blacklisted = false) {
        const tokenDoc = await this.Token.create({
            token,
            user: userId,
            expires: expires.toDate(),
            type,
            blacklisted,
        });
        return tokenDoc;
    }

    /**
     * Verifies a JWT token and checks its existence in the database.
     * @param {string} token - JWT token
     * @param {string} type - Token type
     * @returns {Promise<Object>} Token document
     */
    async verifyToken(token, type) {
        let payload;
        try {
            payload = jwt.verify(token, this.config.secret);
        } catch (err) {
            throw new Error('Token invalid or expired');
        }
        const tokenDoc = await this.Token.findOne({
            token,
            type,
            user: payload.sub,
            blacklisted: false
        });
        if (!tokenDoc) {
            throw new Error('Token not found');
        }
        return tokenDoc;
    }

    /**
     * Generates access and refresh tokens for authentication.
     * @param {string} userId - User ID
     * @returns {Promise<Object>} Auth tokens object
     */
    async generateAuthTokens(userId) {
        const accessTokenExpires = dayjs().add(
            this.config.jwt.accessExpirationMinutes,
            'minutes',
        );
        const accessToken = this.generateToken(
            userId,
            accessTokenExpires,
            this.tokenTypes.ACCESS,
        );
        const refreshTokenExpires = dayjs().add(
            this.config.jwt.refreshExpirationDays,
            'days',
        );
        const refreshToken = this.generateToken(
            userId,
            refreshTokenExpires,
            this.tokenTypes.REFRESH,
        );
        await this.saveToken(
            refreshToken,
            userId,
            refreshTokenExpires,
            this.tokenTypes.REFRESH,
        );
        return {
            access: {
                token: accessToken,
                expires: accessTokenExpires.toDate(),
            },
            refresh: {
                token: refreshToken,
                expires: refreshTokenExpires.toDate(),
            },
        };
    }
}

module.exports = TokenService;
