import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty().withMessage("Email is required")
      .isEmail().withMessage("Email is invalid"),

    body("username")
      .trim()
      .notEmpty().withMessage("Username is required")
      .isLowercase().withMessage("Username must be in lowercase")
      .isLength({ min: 3 }).withMessage("Username must be at least 3 characters long"),

    body("password")
      .trim()
      .notEmpty().withMessage("Password is required")
      .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
  ];
};

const userLoginValidator =() =>{
  return [
    body("email")
       .optional()
       .isEmail()
       .withMessage("Email is invalid"),
    body("password")
       .notEmpty()
       .withMessage("password is required"),
    

  ];
}

export { userRegisterValidator,userLoginValidator };
