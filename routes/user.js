/**
 * oauth2js (https://github.com/ni-c/oauth2js)
 *
 * @file routes/user.js
 * @brief User routes
 * @author Willi Thiel (ni-c@ni-c.de)
 * 
 */
if( typeof define !== 'function') {
	var define = require('amdefine')(module);
}

define(['crypto', 'mongodb'], function(crypto, mongodb) {

	var user = {};

	/**
	 * Index
	 *
	 * @param req The request
	 * @param res The response
	 */
	user.index = function(req, res) {
		// Redirect to login if there is no active user session
		if(!req.session.user) {
			return res.redirect('/login');
		}
		res.render('index', {
			user : req.session.user
		});
	}

	/**
	 * User login
	 *
	 * @param req The request
	 * @param res The response
	 */
	user.login = function(req, res) {
		res.render('login');
	}

	/**
	 * User logout
	 *
	 * @param req The request
	 * @param res The response
	 */
	user.logout = function(req, res) {
		req.session.user = null;
					res.render('login', {message: 'Logout successful.'});
	}
	
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
				'email' : email
			}).toArray(function(err, r) {
				// Wrong password or username
				if((err) || (r.length != 1) || (r[0].password != password)) {
					req.session.user = null;
					res.render('login', {message: 'Wrong email/password combination.'});
				} else {
					// login successful
					req.session.user = r[0];
					if (req.query.response_type == 'token') {
    				var search = req._parsedUrl.search;
						return res.redirect('/authorize' + search)
					} else {
						return res.redirect('/');
					}
				}
			});
		});
	}

	return user;

});
