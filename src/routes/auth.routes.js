import { Router } from "express";
import {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
} from "../controllers/auth-controller.js";

import { validate } from "../middlewares/validator-middleware.js";
import {
  userLoginValidator,
  userRegisterValidator,
} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth-middleware.js";

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

router.post(
  "/refresh-token",
  refreshAccessToken
);

export default router;
