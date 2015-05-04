// Load modules

var Boom = require('boom');
var Hoek = require('hoek');
var Joi = require('joi');

// Declare internals

var internals = {};


exports.register = function (server, options, next) {

    server.auth.scheme('cookie', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};

internals.schema = Joi.object({
    cookie: Joi.string().default('sid'),
    password: Joi.string().required(),
    ttl: Joi.number().integer().min(0).when('keepAlive', { is: true, then: Joi.required() }),
    domain: Joi.string().allow(null),
    path: Joi.string().default('/'),
    clearInvalid: Joi.boolean().default(false),
    keepAlive: Joi.boolean().default(false),
    isSecure: Joi.boolean().default(true),
    isHttpOnly: Joi.boolean().default(true),
    redirectTo: Joi.string().allow(false),
    appendNext: Joi.alternatives(Joi.string(), Joi.boolean()).default(false),
    redirectOnTry: Joi.boolean().default(true),
    validateFunc: Joi.func()
}).required();

internals.implementation = function (server, options) {

    var results = Joi.validate(options, internals.schema);
    Hoek.assert(!results.error, results.error);

    var settings = results.value;

    var cookieOptions = {
        encoding: 'iron',
        password: settings.password,
        isSecure: settings.isSecure,                  // Defaults to true
        path: settings.path,
        isHttpOnly: settings.isHttpOnly,              // Defaults to true
        clearInvalid: settings.clearInvalid,
        ignoreErrors: true
    };

    if (settings.ttl) {
        cookieOptions.ttl = settings.ttl;
    }

    if (settings.domain) {
        cookieOptions.domain = settings.domain;
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
                    session = request.auth.artifacts;
                    Hoek.assert(session, 'No active session to apply key to');

                    session[key] = value;
                    return reply.state(settings.cookie, session);
                }

                Hoek.assert(session && typeof session === 'object', 'Invalid session');
                request.auth.artifacts = session;
                reply.state(settings.cookie, session);
            },
            clear: function (key) {

                if (arguments.length) {
                    Hoek.assert(key && typeof key === 'string', 'Invalid session key');
                    var session = request.auth.artifacts;
                    Hoek.assert(session, 'No active session to clear key from');
                    delete session[key];
                    return reply.state(settings.cookie, session);
                }

                request.auth.artifacts = null;
                reply.unstate(settings.cookie);
            },
            ttl: function (msecs) {

                var session = request.auth.artifacts;
                Hoek.assert(session, 'No active session to modify ttl on');
                reply.state(settings.cookie, session, { ttl: msecs });
            }
        };

        return reply.continue();
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
                    if (settings.keepAlive) {
                        reply.state(settings.cookie, session);
                    }

                    return reply.continue({ credentials: session, artifacts: session });
                }

                settings.validateFunc(session, function (err, isValid, credentials) {

                    if (err ||
                        !isValid) {

                        if (settings.clearInvalid) {
                            reply.unstate(settings.cookie);
                        }

                        return unauthenticated(Boom.unauthorized('Invalid cookie'), { credentials: credentials || session, artifacts: session });
                    }

                    if (settings.keepAlive) {
                        reply.state(settings.cookie, session);
                    }

                    return reply.continue({ credentials: credentials || session, artifacts: session });
                });
            };

            var unauthenticated = function (err, result) {

                if (settings.redirectOnTry === false &&             // Defaults to true
                    request.auth.mode === 'try') {

                    return reply(err, null, result);
                }

                var redirectTo = settings.redirectTo;
                if (request.route.settings.plugins['hapi-auth-cookie'] &&
                    request.route.settings.plugins['hapi-auth-cookie'].redirectTo !== undefined) {

                    redirectTo = request.route.settings.plugins['hapi-auth-cookie'].redirectTo;
                }

                if (!redirectTo) {
                    return reply(err, null, result);
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

                return reply('You are being redirected...', null, result).redirect(uri);
            };

            validate();
        }
    };

    return scheme;
};
