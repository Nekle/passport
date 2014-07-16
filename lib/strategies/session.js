/**
 * Module dependencies.
 */
var pause = require('pause')
  , util = require('util')
  , Strategy = require('passport-strategy');


/**
 * `SessionStrategy` constructor.
 *
 * @api public
 */
function SessionStrategy() {
  Strategy.call(this);
  this.name = 'session';
}

/**
 * Inherit from `Strategy`.
 */
util.inherits(SessionStrategy, Strategy);

/**
 * Authenticate request based on the current session state.
 *
 * The session authentication strategy uses the session to restore any login
 * state across requests.  If a login session has been established, `req.user`
 * will be populated with the current user.
 *
 * This strategy is registered automatically by Passport.
 *
 * @param {Object} req
 * @param {Object} options
 * @api protected
 */
SessionStrategy.prototype.authenticate = function(data, options) {
  if (!data._passport) { return this.error(new Error('passport.initialize() middleware not in use')); }
  options = options || {};

  var self = this
    , su = data._passport.session.user;
  if (su || su === 0) {
    // NOTE: Stream pausing is desirable in the case where later middleware is
    //       listening for events emitted from request.  For discussion on the
    //       matter, refer to: https://github.com/jaredhanson/passport/pull/106
    
    var paused = options.pauseStream ? pause(data) : null;
    data._passport.instance.deserializeUser(su, data, function(err, user) {
      if (err) { return self.error(err); }
      if (!user) {
        delete data._passport.session.user;
//        self.pass();
        if (paused) {
          paused.resume();
        }
        return;
      }
      var property = data._passport.instance._userProperty || 'user';
      data[property] = user;
//      self.pass();
      if (paused) {
        paused.resume();
      }
    });
  } else {
//    self.pass();
  }
};


/**
 * Expose `SessionStrategy`.
 */
module.exports = SessionStrategy;
