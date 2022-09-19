import { AuthenticationError, ForbiddenError } from 'apollo-server-core';
import config from 'config';
import checkIsLoggedIn from '../middleware/checkIsLoggedIn';
import userModel from '../models/user.model';
import redisClient from '../utils/connectRedis';
import { signJwt, verifyJwt } from '../utils/jwt';
import errorHandler from './error.controller';

const accessTokenExpireIn :any = config.get('jwtAccessTokenExpiresIn');
const refreshTokenExpireIn :any= config.get('jwtRefreshTokenExpiresIn');

const cookieOptions = {
  httpOnly: true,
  // domain: 'localhost',
  sameSite: 'none',
  secure: true,
};

const accessTokenCookieOptions = {
  ...cookieOptions,
  maxAge: accessTokenExpireIn * 60 * 1000,
  expires: new Date(Date.now() + accessTokenExpireIn * 60 * 1000),
};

const refreshTokenCookieOptions = {
  ...cookieOptions,
  maxAge: refreshTokenExpireIn * 60 * 1000,
  expires: new Date(Date.now() + refreshTokenExpireIn * 60 * 1000),
};

if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

const signup = async (name: any, email: any, password: any, passwordConfirm: any ) => {
  try {
    const user = await userModel.create({
      name,
      email,
      password,
      passwordConfirm,
    });

    return {
      status: 'success',
      user,
    };
  } catch (error:any) {
    if (error.code === 11000) {
      throw new ForbiddenError('User already exist');
    }
    errorHandler(error);
  }
};

async function signTokens(user:any) {
  // Create a Session
  await redisClient.set(user.id, JSON.stringify(user), {
    EX: 60 * 60,
  });

  // Create access token
  const access_token = signJwt({ user: user.id }, 'JWT_ACCESS_PRIVATE_KEY', {
    expiresIn: `${config.get('jwtAccessTokenExpiresIn')}m`,
  });

  // Create refresh token
  const refresh_token = signJwt({ user: user.id }, 'JWT_REFRESH_PRIVATE_KEY', {
    expiresIn: `${config.get('jwtRefreshTokenExpiresIn')}m`,
  });

  return { access_token, refresh_token };
}

const login = async (parent: any, { input: { email, password } }: any, { req, res }: any) => {
  try {
    // Check if user exist and password is correct
    const user:any = await userModel
      .findOne({ email })
      .select('+password +verified');

    if (!user || !(await user.comparePasswords(password, user.password))) {
      throw new AuthenticationError('Invalid email or password');
    }

    user.password = "";

    // Create a session and tokens
    const { access_token, refresh_token } = await signTokens(user);

    // Add refreshToken to cookie
    res.cookie('refresh_token', refresh_token, refreshTokenCookieOptions);
    res.cookie('access_token', access_token, accessTokenCookieOptions);
    res.cookie('logged_in', true, {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    return {
      status: 'success',
      access_token,
    };
  } catch (error) {
    errorHandler(error);
  }
};

const refreshAccessToken = async (parent: any, args: any, { req, res }: any) => {
  try {
    // Get the refresh token
    const { refresh_token } = req.cookies;

    // Validate the RefreshToken
    const decoded :any = verifyJwt(refresh_token, 'JWT_REFRESH_PUBLIC_KEY');

    if (!decoded) {
      throw new ForbiddenError('Could not refresh access token');
    }

    // Check if user's session is valid
    const session = await redisClient.get(decoded.user);

    if (!session) {
      throw new ForbiddenError('User session has expired');
    }

    // Check if user exist and is verified
    const user = await userModel
      .findById(JSON.parse(session)._id)
      .select('+verified');

    if (!user || !user.verified) {
      throw new ForbiddenError('Could not refresh access token');
    }

    // Sign new access token
    const access_token = signJwt({ user: user._id }, 'JWT_ACCESS_PRIVATE_KEY', {
      expiresIn: config.get('jwtAccessTokenExpiresIn'),
    });

    // Send access token cookie
    res.cookie('access_token', access_token, accessTokenCookieOptions);
    res.cookie('logged_in', 'true', {
      ...accessTokenCookieOptions,
      httpOnly: false,
    });

    return {
      status: 'success',
      access_token,
    };
  } catch (error) {
    errorHandler(error);
  }
};

const logoutHandler = async (_: any, args: any, { req, res, getAuthUser }: any) => {
  try {
    await checkIsLoggedIn(req, getAuthUser);

    const user = await getAuthUser(req);

    // Delete the user's session
    await redisClient.del(user.id);

    // Logout user
    res.cookie('access_token', '', { maxAge: -1 });
    res.cookie('refresh_token', '', { maxAge: -1 });
    res.cookie('logged_in', '', { maxAge: -1 });

    return true;
  } catch (error) {
    console.log(error);
    errorHandler(error);
  }
};

export default {
  signup,
  login,
  refreshAccessToken,
  logoutHandler,
};