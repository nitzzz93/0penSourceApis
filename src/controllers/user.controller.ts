import errorHandler from './error.controller.js';
import checkIsLoggedIn from '../middleware/checkIsLoggedIn';

const getMe = async (_: any, args: any, { req, getAuthUser }: any) => {
  try {
    await checkIsLoggedIn(req, getAuthUser);

    const user = await getAuthUser(req);

    return {
      status: 'success',
      user,
    };
  } catch (error) {
    errorHandler(error);
  }
};

export default {
  getMe,
};