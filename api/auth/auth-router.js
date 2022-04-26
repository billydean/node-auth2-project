const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { jwtSecret } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const Users = require('../users/users-model');

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    const {password, username} = req.body;
    const { role_name } = req;
    const hash = bcrypt.hashSync(password, 6);
    Users.add({username, role_name, password: hash})
      .then(registered => {
        res.status(201).json(registered)
      })
      .catch(next)

});


router.post("/login", checkUsernameExists, (req, res, next) => {
  //helper for generating jwt
  console.log(req.user);
  function makeToken(user) {
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name
    }
    const options = {
      expiresIn: '1d',
    }
    return jwt.sign(payload, jwtSecret, options);
  }
  const {password} = req.body;
  if (bcrypt.compareSync(password, req.user.password)) {
    const token = makeToken(req.user);
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token
    })
  } else {
    next({
      status: 401,
      message: "Invalid credentials"
    })
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }


   */
});

module.exports = router;
