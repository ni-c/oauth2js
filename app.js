/**
 * oauth2js (https://github.com/ni-c/oauth2js)
 *
 * @file app.js
 * @brief OAuth application
 * @author Willi Thiel (ni-c@ni-c.de)
 *
 */

/**
 * RequireJS
 * @see http://requirejs.org/docs/node.html
 */
var requirejs = require('requirejs');
requirejs.config({
  nodeRequire: require
});

/**
 * Express
 * @see http://expressjs.com/guide.html
 */
requirejs([ 'http', 'connect', 'path', 'express', 'node-conf', 'mongodb', './routes/oauth', './routes/user' ], function(http, connect, path, express, conf, mongodb, oauth, user) {

	var node_env = process.env.NODE_ENV ? process.env.NODE_ENV : 'development';
  var config = conf.load(node_env);

  // Check for configuration
  if (!config.ports || !config.mongo || !config.mongo.host || !config.mongo.name || !config.mongo.port || !config.secret || !config.oauth) {
    console.log('\u001b[31mMissing configuration file \u001b[33mconfig/' + node_env + '.json\u001b[31m. Create configuration file or start with `NODE_ENV=production node app.js` to use another configuration file.\033[0m');
    return;
  }
  console.log('\u001b[32mUsing configuration \u001b[33mconfig/' + node_env + '.json\u001b[32m...\033[0m');

  var app = express();
  var cookieParser = express.cookieParser(config.secret);
  var sessionStore = new connect.middleware.session.MemoryStore();

  // Initialize database
  var db = new mongodb.Db(config.mongo.name, new mongodb.Server(config.mongo.host, parseInt(config.mongo.port), config.mongo.user, {
    native_parser: false,
    auto_reconnect: true,
    safe: true
  }));

  // Open database
  db.open(function(err, db) {
    if (err) {
      throw new Error(err);
    }

    app.configure(function() {
      app.set('ports', config.ports);
      app.set('views', __dirname + '/views');
      app.set('view engine', 'jade');
      app.set('db', db);
      app.set('oauth', config.oauth);
      app.use(express.favicon());
      app.use(express.logger('dev'));
      app.use(express.bodyParser());
      app.use(express.methodOverride());
      app.use(cookieParser);
      app.use(express.session({
        store: sessionStore
      }));
      app.use(app.router);
    });

    app.configure('development', function() {
      app.use(express.errorHandler());
    });

    // Define OAuth routes
    app.post('/token', oauth.token);
    app.get('/authorize', oauth.authorize);
    
    // Define User routes
    app.get('/', user.index);
    app.get('/login', user.login);
    app.post('/login', user.performlogin);
    app.get('/logout', user.logout);


		// 404 Not found
    app.all('*', function(req, res) { res.send(404, "<html><body><pre>I'm sorry Dave, i'm afraid i can't do that.</pre></body></html>") });
    
    // Start server
    app.get('ports').forEach(function(port) {
      http.createServer(app).listen(port, function() {
        console.log('\u001b[32mExpress server listening on port \u001b[33m' + port + '\033[0m');
      });
    });
  });
});