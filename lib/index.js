'use strict';

const Boom = require('@hapi/boom');
const Bounce = require('@hapi/bounce');
const Hoek = require('@hapi/hoek');
const Validate = require('@hapi/validate');


const internals = {};


module.exports = {
    pkg: require('../package.json'),
    requirements: {
        hapi: '>=18.4.0'
    },
    register: (server, options) => {

        server.auth.scheme('cookie', internals.implementation);
    }
};


internals.schema = Validate.object({
    appendNext: Validate.alternatives([
        Validate.string(),
        Validate.boolean(),
        Validate.object({ raw: Validate.boolean(), name: Validate.string() })
    ])
        .default(false),

    cookie: Validate.object({
        name: Validate.string().default('sid'),
        encoding: Validate.valid('iron').default('iron'),
        password: Validate.required(),
        ignoreErrors: Validate.valid(true).default(true)
    })
        .unknown()
        .default(),

    keepAlive: Validate.boolean()
        .when('cookie.ttl', { is: Validate.number().min(1), otherwise: Validate.forbidden() })
        .default(false),

    redirectTo: Validate.alternatives([
        Validate.string(),
        Validate.func()
    ])
        .allow(false),

    requestDecoratorName: Validate.string().default('cookieAuth'),
    validateFunc: Validate.func()
})
    .required();


internals.CookieAuth = class {

    constructor(request, settings) {

        this.request = request;
        this.settings = settings;
    }

    set(session, value) {

        const { h, request, settings } = this;

        if (arguments.length > 1) {
            const key = session;
            Hoek.assert(key && typeof key === 'string', 'Invalid session key');
            session = request.auth.artifacts;
            Hoek.assert(session, 'No active session to apply key to');

            session[key] = value;
            return h.state(settings.name, session);
        }

        Hoek.assert(session && typeof session === 'object', 'Invalid session');
        request.auth.artifacts = session;
        h.state(settings.name, session);
    }

    clear(key) {

        const { h, request, settings } = this;

        if (arguments.length) {
            Hoek.assert(key && typeof key === 'string', 'Invalid session key');
            const session = request.auth.artifacts;
            Hoek.assert(session, 'No active session to clear key from');
            delete session[key];
            return h.state(settings.name, session);
        }

        request.auth.artifacts = null;
        h.unstate(settings.name);
    }

    ttl(msecs) {

        const { h, request, settings } = this;
        const session = request.auth.artifacts;
        Hoek.assert(session, 'No active session to modify ttl on');
        h.state(settings.name, session, { ttl: msecs });
    }
};


internals.implementation = (server, options) => {

    const settings = Validate.attempt(options, internals.schema);
    settings.name = settings.cookie.name;
    delete settings.cookie.name;

    server.state(settings.name, settings.cookie);
    settings.cookie = server.states.cookies[settings.name];

    if (typeof settings.appendNext === 'boolean') {
        settings.appendNext = (settings.appendNext ? 'next' : '');
    }

    if (typeof settings.appendNext === 'object') {
        settings.appendNextRaw = settings.appendNext.raw;
        settings.appendNext = settings.appendNext.name || 'next';
    }

    const decoration = (request) => new internals.CookieAuth(request, settings);
    server.decorate('request', settings.requestDecoratorName, decoration, { apply: true });

    server.ext('onPreAuth', (request, h) => {

        // Used for setting and unsetting state, not for replying to request
        request[settings.requestDecoratorName].h = h;

        return h.continue;
    });

    const scheme = {
        authenticate: async (request, h) => {

            const validate = async () => {

                // Check cookie

                const session = request.state[settings.name];
                if (!session) {
                    return unauthenticated(Boom.unauthorized(null, 'cookie'));
                }

                if (!settings.validateFunc) {
                    if (settings.keepAlive) {
                        h.state(settings.name, session);
                    }

                    return h.authenticated({ credentials: session, artifacts: session });
                }

                let credentials = session;

                try {
                    const result = await settings.validateFunc(request, session);

                    Hoek.assert(typeof result === 'object', 'Invalid return from validateFunc');
                    Hoek.assert(Object.prototype.hasOwnProperty.call(result, 'valid'), 'validateFunc must have valid property in return');

                    if (!result.valid) {
                        throw Boom.unauthorized(null, 'cookie');
                    }

                    credentials = result.credentials || credentials;

                    if (settings.keepAlive) {
                        h.state(settings.name, session);
                    }

                    return h.authenticated({ credentials, artifacts: session });
                }
                catch (err) {
                    Bounce.rethrow(err, 'system');

                    if (settings.cookie.clearInvalid) {
                        h.unstate(settings.name);
                    }

                    let unauthorized = Boom.isBoom(err) && err.typeof === Boom.unauthorized ? err : null;
                    if (!unauthorized) {
                        unauthorized = Boom.unauthorized('Invalid cookie');
                        unauthorized.data = err;
                    }

                    return unauthenticated(unauthorized, { credentials, artifacts: session });
                }
            };

            const unauthenticated = (err, result) => {

                let redirectTo = settings.redirectTo;
                if (request.route.settings.plugins['hapi-auth-cookie'] &&
                    request.route.settings.plugins['hapi-auth-cookie'].redirectTo !== undefined) {

                    redirectTo = request.route.settings.plugins['hapi-auth-cookie'].redirectTo;
                }

                let uri = typeof redirectTo === 'function' ? redirectTo(request) : redirectTo;

                if (!uri || request.auth.mode !== 'required') {
                    return h.unauthenticated(err);
                }

                if (settings.appendNext) {
                    if (uri.indexOf('?') !== -1) {
                        uri += '&';
                    }
                    else {
                        uri += '?';
                    }

                    if (settings.appendNextRaw) {
                        uri += settings.appendNext + '=' + encodeURIComponent(request.raw.req.url);
                    }
                    else {
                        uri += settings.appendNext + '=' + encodeURIComponent(request.url.pathname + request.url.search);
                    }
                }

                return h.response('You are being redirected...').takeover().redirect(uri);
            };

            return await validate();
        }
    };

    return scheme;
};
