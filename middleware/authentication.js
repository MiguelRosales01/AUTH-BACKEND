const {isTokenValid, attachCookiesToResponse} = require('../utils/jwt');
const {StatusCodes} = require('http-status-codes');
const Token = require('../models/Token');


const authenticateUser = async (req, res, next) => {
    const { refreshToken, accessToken } = req.signedCookies;
  
    try {
      if (accessToken) {
        const payload = isTokenValid(accessToken);
        req.user = payload.user;
        return next();
      }
      const payload = isTokenValid(refreshToken);
  
      const existingToken = await Token.findOne({
        user: payload.user.userId,
        refreshToken: payload.refreshToken,
      });
  
      if (!existingToken || !existingToken?.isValid) {
        return res.status(StatusCodes.UNAUTHORIZED).json('Invalid credentials');
      }
  
      attachCookiesToResponse({
        res,
        user: payload.user,
        refreshToken: existingToken.refreshToken,
      });
  
      req.user = payload.user;
      next();
    } catch (error) {
        return res.status(StatusCodes.UNAUTHORIZED).json('Invalid credentials');
    }
};


module.exports = authenticateUser;