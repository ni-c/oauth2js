/**
 * oauth2js (https://github.com/ni-c/oauth2js)
 *
 * @file routes/user.js
 * @brief User routes
 * @author Willi Thiel (ni-c@ni-c.de)
 * 
 */
if (typeof define !== 'function') {
  var define = require('amdefine')(module);
}

define([ 'crypto', 'mongodb' ], function(crypto, mongodb) {

  var user = {};

  /**
   * Index
   *
   * @param req The request
   * @param res The response
   */
  user.index = function(req, res) {
    // Redirect to login if there is no active user session
    if (!req.session.user) {
      return res.redirect('/login');
    }
    res.render('index', {
      user: req.session.user.email
    });
  };

  /**
   * User login
   *
   * @param req The request
   * @param res The response
   */
  user.login = function(req, res) {
    if (!req.session.user) {
      res.render('login');
    } else {
      res.redirect('/');
    }
  };

  /**
   * User logout
   *
   * @param req The request
   * @param res The response
   */
  user.logout = function(req, res) {
    if (req.session.user) {
      var user_id = req.session.user._id;
      req.app.get('db').collection('Token', function(err, t) {
        t.update({
          user: user_id
        }, {
          $set: {
            valid: false
          }
        }, {
          multi: true
        }, function(err, r) {
          req.session.user = null;
          res.render('login', {
            message: 'Logout successful.'
          });
        });
      });
    } else {
      res.redirect('/login');
    }
  };

  /**
   * User login
   *
   * @param req The request
   * @param res The response
   */
  user.performlogin = function(req, res) {
    var email = req.body.email;
    var password = crypto.createHash('sha256').update(req.body.password).digest("hex");

    req.app.get('db').collection('User', function(err, u) {
      u.find({
        'email': email
      }).toArray(function(err, r) {
        // Wrong password or username
        if ((err) || (r.length != 1) || (r[0].password != password)) {
          req.session.user = null;
          res.render('login', {
            message: 'Wrong email/password combination.'
          });
        } else {
          // Login successful
          req.session.user = r[0];
          // If redirect URL is set
          if (req.session.redirectto) {
            var redirectto = req.session.redirectto;
            req.session.redirectto = null;
            return res.redirect(redirectto);
          } else {
            return res.redirect('/');
          }
        }
      });
    });
  };

  return user;

});
