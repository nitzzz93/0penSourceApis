import authController from '../controllers/auth.controller';
import userController from '../controllers/user.controller';

export default {
  // Users
  getMe: userController.getMe,
  // Auth
  refreshAccessToken: authController.refreshAccessToken,
  logoutUser: authController.logoutHandler,
};