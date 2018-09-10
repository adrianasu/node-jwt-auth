'use strict';
const express = require('express');
const passport = require('passport');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const config = require('../config');
const router = express.Router();

// Create a signed JWT including info about the user in the payload
const createAuthToken = function(user) {
  return jwt.sign({user}, config.JWT_SECRET, {
    subject: user.username,
    expiresIn: config.JWT_EXPIRY,
    algorithm: 'HS256'
  });
};

// to use our local authentication strategy we call
// passport.authenticate('local', {session: false}), 
// which returns a middleware function.
const localAuth = passport.authenticate('local', {session: false});
router.use(bodyParser.json());
// The user provides a username and password to login
router.post('/login', localAuth, (req, res) => {
  // req.user points to the user object fetched from the db
  const authToken = createAuthToken(req.user.serialize());
  res.json({authToken});
});

const jwtAuth = passport.authenticate('jwt', {session: false});

// The user exchanges a valid JWT for a new one with a later expiration
// The endpoint is protected using the JWT strategy
router.post('/refresh', jwtAuth, (req, res) => {
  // req.user points to the representation of the user decoded from
  // the payload
  const authToken = createAuthToken(req.user);
  res.json({authToken});
});

module.exports = {router};
