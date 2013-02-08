if (typeof define !== 'function') {
  var define = require('amdefine')(module);
}

define(function(require) {
  var routes = {};

  verify = function(req, res) {

    var oauth_base = req.app.get('oauth')._baseSite;

    // Verify access token
    req.app.get('oauth').get(oauth_base + "verify", req.session.access_token, function(error, data, response) {

      // Not verified
      if (error) {

        req.session.access_token = null;

        // Build authorize URL
        var authorize_url = req.app.get('oauth').getAuthorizeUrl({
          response_type: "token",
          redirect_uri: req.app.get('redirect_uri'),
          state: "authorization"
        });

        res.render('index', {
          message: 'Not logged in.',
          url: authorize_url,
          url_type: 'Authorize URL: '
        });

      } else {

        // Login OK
        if (response.statusCode == 200) {

          // Build logout URL
          var logout_url = oauth_base + "logout";

          res.render('index', {
            message: 'Token: \n' + data,
            url: logout_url,
            url_type: 'Logout URL: '
          });
        }
      }
    });
  };

  routes.index = function(req, res) {

    // Coming back from authorization
    if (req.query.state == "authorization") {
      var code = req.query.access_token;
      req.app.get('oauth').getOAuthAccessToken(code, {
        'grant_type': 'authorization_code',
        'redirect_uri': req.app.get('redirect_uri')
      }, function(err, access_token, refresh_token, results) {
        req.session.access_token = access_token;
        verify(req, res);
        res.redirect('/');
      });
    } else {
      verify(req, res);
    }
  };

  return routes;
});