/**
 * This enables authentication for the admin pages.
 * All paths starting with /admin/ are protected by cookie-based login, where
 * username must match `admin.username` and the password's bcrypt hash must match
 * `admin.password_hash`.
 */

var cookieParser = require('cookie-parser')
  , serveStatic = require('serve-static')
  , session = require('express-session')
  , bodyParser = require('body-parser')
  , auth = require('connect-auth')
  , path = require('path')
  , authStrategy = require('./strategy')

module.exports = function (app, hexo) {
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(cookieParser());
  app.use(session({
      resave: false,
      saveUninitialized: false,
      secret: hexo.config.admin.secret
  }));

  let adminRoot = (hexo.config.admin || {}).root ? hexo.config.admin.root + 'admin' : 'admin';

  app.use(hexo.config.root + adminRoot, auth(new authStrategy(hexo)));
  app.use(hexo.config.root + adminRoot + '/login', function (req, res) {
      if (req.method === 'POST') {
          req.authenticate(['adminAuth'], function(error, done) {
              if (done) {
                  res.writeHead(302, { 'Location':  hexo.config.root + adminRoot });
                  res.end();
              }
          });
      } else {
          serveStatic(path.join(__dirname, '../www', 'login'))(req, res);
      }
  });
  app.use(hexo.config.root + adminRoot, function (req, res, next) {
      req.authenticate(['adminAuth'], next)
  });
}
