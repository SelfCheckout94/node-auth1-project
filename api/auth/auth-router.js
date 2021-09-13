// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const User = require("./../users/users-model");
const bcrypt = require("bcryptjs");

const {
  checkUsernameExists,
  checkUsernameFree,
  checkPasswordLength,
} = require("./auth-middleware");

router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const hash = bcrypt.hashSync(password, 8);
      const newUser = { username, password: hash };

      const user = await User.add(newUser);

      res.json(user);
    } catch (err) {
      next(err);
    }
  }
);

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;
    if (req.user && bcrypt.compareSync(password, req.user.password)) {
      req.session.user = req.user;
      res.json({
        status: 200,
        message: `Welcome ${req.user.username}!`,
      });
    } else {
      next({
        status: 401,
        message: "Invalid credentials",
      });
    }
  } catch (err) {
    next(err);
  }
});
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

// Don't forget to add the router to the `exports` object so it can be required in other modules

module.exports = router;
