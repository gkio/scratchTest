var express = require('express');
var passport = require('passport');
// var Account = require('../models/account');
var bcrypt = require('bcrypt-nodejs')
var async = require('async');
var crypto = require('crypto');
var nodemailer = require('nodemailer')
var router = express.Router();

var mongoose = require('mongoose');
var Schema = mongoose.Schema;
// var bcrypt = require('bcrypt-nodejs')
var passportLocalMongoose = require('passport-local-mongoose');

var Account = new mongoose.Schema({
    username: {type: String, required: true, unique: true },
    password: String,
    email:{type: String, required: true, unique: true },
    leagueServer:String,
    leagueName:String,
    balance:Number,
    scratchCards:Number,
    resetPasswordToken: String,
    resetPasswordExpires: Date
});
Account.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});
Account.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};
Account.plugin(passportLocalMongoose);

router.get('/', function (req, res) {
    res.render('index', { user : req.user });
});
router.get('/register', function(req, res) {
  res.render('register', {
    user: req.user
  });
});
// router.get('/register', function(req, res) {
//     res.render('register', { });
// });
router.get('/forgot', function(req, res) {
  res.render('forgot', {
    user: req.user
  });
});
router.post('/register', function(req, res) {
  var user = new Account({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      balance:0,
      scratchCards:0
    });

  user.save(function(err) {
    req.logIn(user, function(err) {
      res.redirect('/');
    });
  });
});

router.get('/login', function(req, res) {
    res.render('login', { user : req.user });
});


router.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    if (!user) {
      return res.redirect('/register')
    }
    req.logIn(user, function(err) {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

router.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      Account.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var transporter = nodemailer.createTransport('smtps://konoko96@gmail.com:giorgos2310278465@smtp.gmail.com');
      var mailOptions = {
        to: user.email,
        from: 'passwordreset@demo.com',
        subject: 'Node.js Password Reset',
        // text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
        //   'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
        //   'http://' + req.headers.host + '/reset/' + token + '\n\n' +
        //   'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        html:'<h1>http://' + req.headers.host + '/reset/' + token+'</h1>'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});

router.get('/reset/:token', function(req, res) {
  Account.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});
router.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      Account.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.logIn(user, function(err) {
            done(err, user);
          });
        });
      });
    },
  ], function(err) {
    res.redirect('/');
  });
});
module.exports = router;