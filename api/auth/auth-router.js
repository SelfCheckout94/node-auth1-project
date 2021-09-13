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

router.get("/logout", (req, res) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        res.json({
          message: "you cannot log out... for some reason",
        });
      } else {
        res.json({
          message: "logged out",
        });
      }
    });
  } else {
    res.json({
      message: "no session",
    });
  }
});

module.exports = router;
