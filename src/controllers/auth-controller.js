import { User } from "../models/user_models.js";
import { ApiResponse } from "../utlis/api-response.js";
import { ApiError } from "../utlis/api-error.js";
import { asyncHandler } from "../utlis/async-handler.js";
import {
  emailVerificationMailgenContent,
  sendEmail,
} from "../utlis/mail.js";

import { verifyJWT } from "../middlewares/auth-middleware.js";

/* ================= TOKENS ================= */

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    if (!user.generateAccessToken || !user.generateRefreshToken) {
      throw new ApiError(500, "Token methods not defined on user model");
    }

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    console.error("TOKEN ERROR 👉", error);
    throw error;
  }
};


/* ================= REGISTER USER ================= */

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  const existedUser = await User.findOne({
    $or: [{ userName:username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(
      409,
      "User with email or username already exists"
    );
  }

  const user = await User.create({
    email,
    userName:username,
    password,
    role,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get(
        "host"
      )}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  if (!createdUser) {
    throw new ApiError(
      500,
      "Something went wrong while registering user"
    );
  }

  return res.status(201).json(
    new ApiResponse(
      201,
      { user: createdUser },
      "User registered successfully. Verification email sent."
    )
  );
});


const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "Email and password are required");
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid credentials");
  }

  const { accessToken, refreshToken } =
    await generateAccessAndRefreshTokens(user._id);

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  if (!req.user) {
    throw new ApiError(401, "Unauthorized");
  }

  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "",
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true, // ⚠️ in dev, see note below
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});




export { registerUser, generateAccessAndRefreshTokens , login ,logoutUser};
