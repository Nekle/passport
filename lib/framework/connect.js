/**
 * Module dependencies.
 */
var initialize = require('../middleware/initialize')
  , authenticate = require('../middleware/authenticate');

module.exports = function() {

  return {
    initialize: initialize,
    authenticate: authenticate
  };
};
