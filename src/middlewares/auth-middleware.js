import jwt from "jsonwebtoken";
import { User } from "../models/user_models.js";
import { ApiError } from "../utlis/api-error.js";
import { asyncHandler } from "../utlis/async-handler.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new ApiError(401, "Unauthorized request");
  }

  try {
    const decodedToken = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
    );

    if (!user) {
      throw new ApiError(401, "Invalid access token");
    }

    req.user = user; // attach user to request
    next();
  } catch (error) {
    throw new ApiError(401, "Invalid or expired access token");
  }
});
