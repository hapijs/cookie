'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');

// Declare internals

const internals = {};


exports.register = function (server, options, next) {

    server.auth.scheme('cookie', internals.implementation);
    next();
};


exports.register.attributes = {
    pkg: require('../package.json')
};

internals.schema = Joi.object({
    cookie: Joi.string().default('sid'),
    password: Joi.alternatives(Joi.string(), Joi.object().type(Buffer)).required(),
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
    validateFunc: Joi.func(),
    requestDecoratorName: Joi.string().default('cookieAuth')
}).required();

internals.implementation = function (server, options) {

    const results = Joi.validate(options, internals.schema);
    Hoek.assert(!results.error, results.error);

    const settings = results.value;

    const cookieOptions = {
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

    const decoration = function (request) {

        const CookieAuth = function () {

            const self = this;

            this.set = function (session, value) {

                const reply = self.reply;

                if (arguments.length > 1) {
                    const key = session;
                    Hoek.assert(key && typeof key === 'string', 'Invalid session key');
                    session = request.auth.artifacts;
                    Hoek.assert(session, 'No active session to apply key to');

                    session[key] = value;
                    return reply.state(settings.cookie, session);
                }

                Hoek.assert(session && typeof session === 'object', 'Invalid session');
                request.auth.artifacts = session;
                reply.state(settings.cookie, session);
            };

            this.clear = function (key) {

                const reply = self.reply;

                if (arguments.length) {
                    Hoek.assert(key && typeof key === 'string', 'Invalid session key');
                    const session = request.auth.artifacts;
                    Hoek.assert(session, 'No active session to clear key from');
                    delete session[key];
                    return reply.state(settings.cookie, session);
                }

                request.auth.artifacts = null;
                reply.unstate(settings.cookie);
            };

            this.ttl = function (msecs) {

                const reply = self.reply;
                const session = request.auth.artifacts;
                Hoek.assert(session, 'No active session to modify ttl on');
                reply.state(settings.cookie, session, { ttl: msecs });
            };
        };

        return new CookieAuth();
    };

    server.decorate('request', settings.requestDecoratorName, decoration, { apply: true });

    server.ext('onPreAuth', (request, reply) => {

        // Used for setting and unsetting state, not for replying to request
        request[settings.requestDecoratorName].reply = reply;

        return reply.continue();
    });

    const scheme = {
        authenticate: function (request, reply) {

            const validate = function () {

                // Check cookie

                const session = request.state[settings.cookie];
                if (!session) {
                    return unauthenticated(Boom.unauthorized(null, 'cookie'));
                }

                if (!settings.validateFunc) {
                    if (settings.keepAlive) {
                        reply.state(settings.cookie, session);
                    }

                    return reply.continue({ credentials: session, artifacts: session });
                }

                settings.validateFunc(request, session, (err, isValid, credentials) => {

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

            const unauthenticated = function (err, result) {

                if (settings.redirectOnTry === false &&             // Defaults to true
                    request.auth.mode === 'try') {

                    return reply(err, null, result);
                }

                let redirectTo = settings.redirectTo;
                if (request.route.settings.plugins['hapi-auth-cookie'] &&
                    request.route.settings.plugins['hapi-auth-cookie'].redirectTo !== undefined) {

                    redirectTo = request.route.settings.plugins['hapi-auth-cookie'].redirectTo;
                }

                if (!redirectTo) {
                    return reply(err, null, result);
                }

                let uri = redirectTo;
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
