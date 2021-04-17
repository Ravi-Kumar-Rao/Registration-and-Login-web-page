const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
//const jwt = require('jsonwebtoken');
// Load User model
const User = require('../models/User');
const { forwardAuthenticated } = require('../config/auth');


// Login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// Register Page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// Register
router.post('/register', (req, res) => {
  const { firstname, lastname, email, password, phone } = req.body;
  let errors = [];

  if (!firstname || !lastname || !email || !password || !phone) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if(phone.length!=10){
    errors.push({ msg: 'Phone Number must be at least 10 digits' });
  }
  if (errors.length > 0) {
    res.render('register', {
      errors,
      firstname,
      lastname,
      email,
      password,
      phone
    });
  } else {
     User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          firstname,
          lastname,
          email,
          password,
          phone
        });
      } else {
        const newUser = new User({
          firstname,
          lastname,
          email,
          password,
          phone
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  'Registration Done Successfully, Now you can log in'
                );
                res.redirect('/users/login');
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});

// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true
  })(req, res, next);
});

// Logout
router.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out Successfully');
  res.redirect('/users/login');
});

module.exports = router;
