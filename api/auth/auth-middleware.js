const User = require("./../users/users-model");

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
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

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
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

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
};
