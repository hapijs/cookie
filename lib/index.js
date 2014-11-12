// Load modules

var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};


exports.register = function (plugin, options, next) {

    plugin.auth.scheme('cookie', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};


internals.implementation = function (server, options) {

    Hoek.assert(options, 'Missing cookie auth strategy options');
    Hoek.assert(!options.validateFunc || typeof options.validateFunc === 'function', 'Invalid validateFunc method in configuration');
    Hoek.assert(options.password, 'Missing required password in configuration');

    var settings = Hoek.clone(options);                        // Options can be reused
    settings.cookie = settings.cookie || 'sid';

    var cookieOptions = {
        encoding: 'iron',
        password: settings.password,
        isSecure: settings.isSecure !== false,                  // Defaults to true
        path: '/',
        isHttpOnly: settings.isHttpOnly !== false               // Defaults to true
    };

    if (settings.ttl) {
        cookieOptions.ttl = settings.ttl;
    }

    if (settings.domain) {
        cookieOptions.domain = settings.domain;
    }

    if (settings.path) {
        cookieOptions.path = settings.path;
    }

    if (typeof settings.appendNext === 'boolean') {
        settings.appendNext = (settings.appendNext ? 'next' : '');
    }

    server.state(settings.cookie, cookieOptions);

    server.ext('onPreAuth', function (request, reply) {

        request.auth.session = {
            set: function (session, value) {

                if (arguments.length > 1) {
                    var key = session;
                    Hoek.assert(key && typeof key === 'string', 'Invalid session key');
                    session = request.state[settings.cookie];
                    Hoek.assert(session && typeof session === 'object', 'Missing or invalid session to apply key to');

                    session[key] = value;
                    return reply.state(settings.cookie, session);
                }

                Hoek.assert(session && typeof session === 'object', 'Invalid session');
                reply.state(settings.cookie, session);
            },
            clear: function (key) {

                if (arguments.length) {
                    Hoek.assert(key && typeof key === 'string', 'Invalid session key');
                    var session = request.state[settings.cookie];
                    Hoek.assert(session && typeof session === 'object', 'Missing or invalid session to clear key from');
                    delete session[key];
                    return reply.state(settings.cookie, session);
                }

                reply.unstate(settings.cookie);
            }
        };

        reply();
    });

    var scheme = {
        authenticate: function (request, reply) {

            var validate = function () {

                // Check cookie

                var session = request.state[settings.cookie];
                if (!session) {
                    return unauthenticated(Boom.unauthorized(null, 'cookie'));
                }

                if (!settings.validateFunc) {
                    return reply(null, { credentials: session });
                }

                settings.validateFunc(session, function (err, isValid, credentials) {

                    if (err ||
                        !isValid) {

                        if (settings.clearInvalid) {
                            reply.unstate(settings.cookie);
                        }

                        return unauthenticated(Boom.unauthorized('Invalid cookie'), { credentials: credentials, log: (err ? { data: err } : 'Failed validation') });
                    }

                    return reply(null, { credentials: credentials || session });
                });
            };

            var unauthenticated = function (err, result) {

                if (settings.redirectOnTry === false &&             // Defaults to true
                    request.auth.mode === 'try') {

                    return reply(err, result);
                }

                var redirectTo = settings.redirectTo;
                if (request.route.plugins['hapi-auth-cookie'] &&
                    request.route.plugins['hapi-auth-cookie'].redirectTo !== undefined) {

                    redirectTo = request.route.plugins['hapi-auth-cookie'].redirectTo;
                }

                if (!redirectTo) {
                    return reply(err, result);
                }

                var uri = redirectTo;
                if (settings.appendNext) {
                    if (uri.indexOf('?') !== -1) {
                        uri += '&';
                    }
                    else {
                        uri += '?';
                    }

                    uri += settings.appendNext + '=' + encodeURIComponent(request.url.path);
                }

                return reply('You are being redirected...', result).redirect(uri);
            };

            validate();
        }
    };

    return scheme;
};

