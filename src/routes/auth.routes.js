import { Router } from "express";
import {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  changePassword,
  forgotPassword,
  resetPassword,
} from "../controllers/auth-controller.js";

import { verifyJWT } from "../middlewares/auth-middleware.js";
import { validate } from "../middlewares/validator-middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
} from "../validators/index.js";

const router = Router();

/* ================= AUTH ================= */

router.post(
  "/register",
  userRegisterValidator(),
  validate,
  registerUser
);

router.post(
  "/login",
  userLoginValidator(),
  validate,
  login
);

router.post(
  "/logout",
  verifyJWT,
  logoutUser
);

router.post(
  "/refresh-token",
  refreshAccessToken
);

/* ================= USER ================= */

router.get(
  "/me",
  verifyJWT,
  getCurrentUser
);

router.get(
  "/verify-email/:verificationToken",
  verifyEmail
);

router.post(
  "/resend-verification",
  verifyJWT,
  resendEmailVerification
);

/* ================= PASSWORD ================= */

router.post(
  "/change-password",
  verifyJWT,
  changePassword
);

router.post(
  "/forgot-password",
  forgotPassword
);

router.post(
  "/reset-password/:resetToken",
  resetPassword
);

export default router;

