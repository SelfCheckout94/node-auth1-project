const User = require("./../users/users-model");

function restricted(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    next({
      status: 401,
      message: "You shall not pass!",
    });
  }
}

async function checkUsernameFree(req, res, next) {
  try {
    const { username } = req.body;
    const [existingUser] = await User.findBy({ username });
    if (existingUser) {
      next({
        status: 422,
        message: "Username taken",
      });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
}

async function checkUsernameExists(req, res, next) {
  try {
    const { username } = req.body;
    const [givenUsername] = await User.findBy({ username });
    if (givenUsername) {
      req.user = givenUsername;
      next();
    } else {
      next({
        status: 401,
        message: "Invalid credentials",
      });
    }
  } catch (err) {
    next(err);
  }
}

async function checkPasswordLength(req, res, next) {
  try {
    const { password } = req.body;
    if (!password || password.length <= 3) {
      next({
        status: 422,
        message: "Password must be longer than 3 chars",
      });
    } else {
      next();
    }
  } catch (err) {
    next(err);
  }
}

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
};
