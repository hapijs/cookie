'use strict';

// Load modules

const Boom = require('boom');
const Hapi = require('hapi');
const Hoek = require('hoek');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const { describe, it, expect } = lab;


// Helpers
const Helpers = require('./helpers');


describe('scheme', () => {

    it('fails with no plugin options', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        expect(() => {

            server.auth.strategy('session', 'cookie', {});
        }).to.throw(Error);
    });

    it('passes with a password configured', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        expect(() => {

            server.auth.strategy('session', 'cookie', { password: 'password-should-be-32-characters' });
            server.auth.default('session');
        }).to.not.throw();
    });

    it('passes with a password configured which is a Buffer', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        expect(() => {

            server.auth.strategy('session', 'cookie', { password: Buffer.from('foobar') });
        }).to.not.throw();
    });

    it('fails if validateFunc is not a function', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        expect(() => {

            server.auth.strategy('session', 'cookie', { validateFunc: 'not a function' });
        }).to.throw(Error);
    });

    it('fails if keepAlive is configured but not ttl', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        expect(() => {

            server.auth.strategy('session', 'cookie', {
                password: 'password-should-be-32-characters',
                keepAlive: true
            });
        }).to.throw(Error);
    });

    it('authenticates a request', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('session', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });

        server.auth.default('session');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/valid');

        expect(res.result).to.equal('valid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.headers['set-cookie']).to.not.exist();
        expect(res2.result).to.equal('resource');
    });

    it('fails over to another strategy if not present', async () => {

        const extraSchemePlugin = {
            register: function (server, options) {

                const simpleTestSchema = function () {

                    return {
                        authenticate: function (request, h) {

                            return h.authenticated({ credentials: { test: 'valid' } });
                        }
                    };
                };

                server.auth.scheme('simpleTest', simpleTestSchema);
            },
            name: 'simpleTestAuth'
        };

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });
        server.auth.default('default');

        server.register(extraSchemePlugin);

        server.auth.strategy('simple', 'simpleTest');

        server.route({
            method: 'GET',
            path: '/multiple',
            config: {
                auth: {
                    mode: 'try',
                    strategies: ['default', 'simple']
                },
                handler: function (request, h) {

                    const credentialsTest = (request.auth.credentials && request.auth.credentials.test) || 'NOT AUTH';
                    return h.response('multiple ' + credentialsTest);
                }
            }
        });

        const res = await server.inject('/multiple');

        expect(res.statusCode).to.equal(200);
        expect(res.result).to.equal('multiple valid');
    });

    it('ends a session', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });
        server.auth.default('default');

        server.route({
            method: 'GET', path: '/login/{user}',
            config: {
                auth: { mode: 'try' },
                handler: function (request, h) {

                    request.cookieAuth.set({ user: request.params.user });
                    return h.response(request.params.user);
                }
            }
        });

        server.route({
            method: 'GET', path: '/logout', handler: function (request, h) {

                request.cookieAuth.clear();
                return h.response('logged-out');
            }
        });

        const res = await server.inject('/login/valid');

        expect(res.result).to.equal('valid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/logout', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.result).to.equal('logged-out');
        expect(res2.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
    });

    it('fails a request with invalid session', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/invalid');

        expect(res.result).to.equal('invalid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict; Domain=example.com; Path=/');
        expect(res2.statusCode).to.equal(401);
    });

    it('does not clear a request with invalid session (clearInvalid not set)', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: false,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/invalid');

        expect(res.result).to.equal('invalid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.headers['set-cookie']).to.not.exist();
        expect(res2.statusCode).to.equal(401);
    });

    it('logs in and authenticates a request', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            cookie: 'special',
            clearInvalid: true
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/steve');

        expect(res.result).to.equal('steve');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.result).to.equal('resource');
    });

    it('errors in validation function', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            cookie: 'special',
            clearInvalid: true,
            validateFunc: function (request, session) {

                throw new Error('boom');
            }
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/steve');

        expect(res.result).to.equal('steve');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(401);
    });

    it('uauthorized error in validation function fails over to subsequent authentication scheme', async () => {

        const plugin = {
            name: 'bogusAuth',
            register: (server, options) => {

                const schema = () => {

                    return {
                        authenticate: (request, h) => {

                            return h.authenticated({ credentials: { user: 'bogus-user' } });
                        }
                    };
                };
                server.auth.scheme('bogus', schema);
            }
        };

        const server = Hapi.server();
        await server.register(require('../'));
        await server.register(plugin);
        server.auth.strategy('first', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            cookie: 'first',
            validateFunc: function (request, session) {

                throw Boom.unauthorized(null, 'first');
            }
        });

        server.auth.strategy('second', 'bogus');

        server.route({
            method: 'GET', path: '/login/{user}',
            config: {
                handler: function (request, h) {

                    request.cookieAuth.set({ user: request.params.user });
                    return h.response(request.params.user);
                }
            }
        });

        server.route({
            method: 'GET', path: '/resource',
            config: {
                auth: { mode: 'required', strategies: ['first', 'second'] },
                handler: function (request, h) {

                    return h.response('valid-resource');
                }
            }
        });

        const res = await server.inject('/login/bob');

        expect(res.result).to.equal('bob');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'first=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.headers['set-cookie']).to.not.exist();
        expect(res2.result).to.equal('valid-resource');
        expect(res2.request.auth.isAuthenticated).to.be.true();
        expect(res2.request.auth.credentials.user).to.equal('bogus-user');
    });

    it('authenticates a request (no ttl)', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });
        server.auth.default('default');

        server.route({
            method: 'GET', path: '/login/{user}',
            config: {
                auth: { mode: 'try' },
                handler: function (request, h) {

                    request.cookieAuth.set({ user: request.params.user });
                    return h.response(request.params.user);
                }
            }
        });

        const res = await server.inject('/login/valid');

        expect(res.result).to.equal('valid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.not.contain('Max-Age');
    });

    it('authenticates a request (no session override)', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            path: '/example-path',
            clearInvalid: true,
            validateFunc: function (request, session) {

                return {
                    valid: session.user === 'valid'
                };
            }
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/valid');

        expect(res.result).to.equal('valid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.result).to.equal('resource');
    });

    it('authenticates a request (no session override) on a sub-path', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            path: '/subpath',
            clearInvalid: true,
            validateFunc: function (request, session) {

                return {
                    valid: session.user === 'valid'
                };
            }
        });
        server.auth.default('default');

        server.route({
            method: 'GET', path: '/subpath/login/{user}',
            config: {
                auth: { mode: 'try' },
                handler: function (request, h) {

                    request.cookieAuth.set({ user: request.params.user });
                    return h.response(request.params.user);
                }
            }
        });

        server.route({
            method: 'GET', path: '/subpath/resource', handler: function (request, h) {

                return h.response('resource');
            }
        });

        const res = await server.inject('/subpath/login/valid');

        expect(res.result).to.equal('valid');
        const header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);
        expect(header[0]).to.contain('Path=/subpath');

        const res2 = await server.inject({ method: 'GET', url: '/subpath/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.result).to.equal('resource');
    });

    it('extends ttl automatically', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            keepAlive: true
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/valid');

        let header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        header = res2.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
    });

    it('extends ttl automatically (validateFunc)', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            domain: 'example.com',
            cookie: 'special',
            clearInvalid: true,
            keepAlive: true,
            validateFunc: function (request, session) {

                const override = Hoek.clone(session);
                override.something = 'new';

                return {
                    valid: session.user === 'valid',
                    credentials: override
                };
            }
        });
        server.auth.default('default');

        Helpers.loginWithResourceEndpoint(server);

        const res = await server.inject('/login/valid');

        expect(res.result).to.equal('valid');
        let header = res.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
        const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

        const res2 = await server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } });

        expect(res2.statusCode).to.equal(200);
        expect(res2.result).to.equal('resource');

        header = res2.headers['set-cookie'];
        expect(header.length).to.equal(1);
        expect(header[0]).to.contain('Max-Age=60');
    });

    it('errors if ignoreIfDecorated is false and the request object is already decorated', async () => {

        const password = 'password-should-be-32-characters';
        const ignoreIfDecorated = false;
        const options = { password, ignoreIfDecorated };

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', options);

        expect(() => {

            server.auth.strategy('default', 'cookie', options);
        }).to.throw(Error);
    });

    describe('set()', () => {

        it('errors on missing session in set()', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.set();
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('Invalid session');
        });

        it('sets individual cookie key', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        request.cookieAuth.set({ user: request.params.user });
                        return h.response(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/setKey', handler: function (request, h) {

                    request.cookieAuth.set('key', 'value');
                    return null;
                }
            });

            const res = await server.inject('/login/steve');

            const pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
            expect(res.result).to.equal('steve');
            const header = res.headers['set-cookie'];
            expect(header.length).to.equal(1);
            expect(header[0]).to.contain('Max-Age=60');
            const cookie = header[0].match(pattern);

            const res2 = await server.inject({ method: 'GET', url: '/setKey', headers: { cookie: 'special=' + cookie[1] } });

            expect(res2.statusCode).to.equal(200);
        });

        it('throws on missing session when trying to set key', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.set('key', 'value');
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('No active session to apply key to');
        });

        it('throws when trying to set key with invalid input', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.set({}, 'value');
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('Invalid session key');
        });

        it('throws when trying to set key with null key', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.set(null, 'value');
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('Invalid session key');
        });
    });

    describe('clear()', () => {

        it('clear a specific session key', async (done) => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        request.cookieAuth.set({ user: request.params.user });
                        return h.response(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/clearKey', handler: function (request, h) {

                    request.cookieAuth.clear('key');
                    return null;
                }
            });

            const res = await server.inject('/login/steve');

            const pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
            expect(res.result).to.equal('steve');
            const header = res.headers['set-cookie'];
            expect(header.length).to.equal(1);
            expect(header[0]).to.contain('Max-Age=60');
            const cookie = header[0].match(pattern);

            const res2 = await server.inject({ method: 'GET', url: '/clearKey', headers: { cookie: 'special=' + cookie[1] } });

            expect(res2.statusCode).to.equal(200);
        });

        it('throws when trying to clear a key on missing session', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.clear('key');
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('No active session to clear key from');
        });

        it('throws when trying to clear a key with invalid input', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.clear({});
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('Invalid session key');
        });

        it('throws when trying to clear a key with null input', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        try {
                            request.cookieAuth.clear(null);
                        }
                        catch (error) {
                            return h.response(error.message);
                        }

                        return h.response('ok');
                    }
                }
            });

            const res = await server.inject('/login/steve');

            expect(res.result).to.equal('Invalid session key');
        });
    });

    describe('ttl()', () => {

        it('overrides ttl', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 1000,
                cookie: 'special',
                clearInvalid: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, h) {

                        request.cookieAuth.set({ user: request.params.user });
                        request.cookieAuth.ttl(60 * 1000);
                        return h.response(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/ttl', handler: function (request, h) {

                    request.cookieAuth.set('key', 'value');
                    return null;
                }
            });

            const res = await server.inject('/login/steve');

            const pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
            expect(res.result).to.equal('steve');
            const header = res.headers['set-cookie'];
            expect(header.length).to.equal(1);
            expect(header[0]).to.contain('Max-Age=60');
            const cookie = header[0].match(pattern);

            const res2 = await server.inject({ method: 'GET', url: '/ttl', headers: { cookie: 'special=' + cookie[1] } });

            expect(res2.statusCode).to.equal(200);
        });
    });

    describe('redirection', () => {

        it('sends to login page (uri without query)', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login',
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', handler: function (request, h) {

                    return h.response('never');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(302);
            expect(res.headers.location).to.equal('http://example.com/login?next=%2F');
        });

        it('sends to login page when redirectTo is a function', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: (request) => 'http://example.com/login?widget=' + request.query.widget,
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', handler: function (request, h) {

                    return h.response('never');
                }
            });

            const res = await server.inject('/?widget=foo');

            expect(res.statusCode).to.equal(302);
            expect(res.headers.location).to.equal('http://example.com/login?widget=foo&next=%2F%3Fwidget%3Dfoo');
        });

        it('skips when redirectTo is set to false', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: false,
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET',
                path: '/',
                handler: function (request, h) {

                    return h.response('never');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(401);
        });

        it('skips when redirectTo is set to function that returns falsey value', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: () => false,
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET',
                path: '/',
                handler: function (request, h) {

                    return h.response('never');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(401);
        });

        it('skips when route override', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login',
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET',
                path: '/',
                handler: function (request, h) {

                    return h.response('never');
                },
                config: {
                    plugins: {
                        'hapi-auth-cookie': {
                            redirectTo: false
                        }
                    }
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(401);
        });

        it('sends to login page (uri with query)', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login?mode=1',
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', handler: function () {

                    return 'never';
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(302);
            expect(res.headers.location).to.equal('http://example.com/login?mode=1&next=%2F');
        });

        it('sends to login page and does not append the next query when appendNext is false', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login?mode=1',
                appendNext: false
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', handler: function (request, h) {

                    return h.response('never');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(302);
            expect(res.headers.location).to.equal('http://example.com/login?mode=1');
        });

        it('appends the custom query when appendNext is string', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login?mode=1',
                appendNext: 'done'
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', handler: function (request, h) {

                    return h.response('never');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(302);
            expect(res.headers.location).to.equal('http://example.com/login?mode=1&done=%2F');
        });

        it('redirect for required mode', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login',
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', config: { auth: { mode: 'required' } }, handler: function (request, h) {

                    return h.response('required');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(302);
            expect(res.headers.location).to.equal('http://example.com/login?next=%2F');
        });

        it('skips redirect for try mode', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login',
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', config: { auth: { mode: 'try' } }, handler: function (request, h) {

                    return h.response('try');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(200);
        });

        it('skips redirect for optional mode', async () => {

            const server = Hapi.server();
            await server.register(require('../'));

            server.auth.strategy('default', 'cookie', {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                redirectTo: 'http://example.com/login',
                appendNext: true
            });
            server.auth.default('default');

            server.route({
                method: 'GET', path: '/', config: { auth: { mode: 'optional' } }, handler: function (request, h) {

                    return h.response('optional');
                }
            });

            const res = await server.inject('/');

            expect(res.statusCode).to.equal(200);
        });
    });

    it('clear cookie on invalid', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        server.auth.strategy('default', 'cookie', {
            password: 'password-should-be-32-characters',
            ttl: 60 * 1000,
            clearInvalid: true
        });
        server.auth.default('default');

        server.route({
            method: 'GET', path: '/', handler: () => null
        });

        const res = await server.inject({ url: '/', headers: { cookie: 'sid=123456' } });

        expect(res.statusCode).to.equal(401);
        expect(res.headers['set-cookie'][0]).to.equal('sid=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict; Path=/');
    });

    it('supports many strategies', async () => {

        const server = Hapi.server();
        await server.register(require('../'));

        expect(() => {

            const options = {
                cookie: 'cookieAuth',
                requestDecoratorName: 'cookieAuth',
                password: 'password-should-be-32-characters'
            };
            server.auth.strategy('default', 'cookie', options);
        }).to.not.throw();

        expect(() => {

            const options = {
                cookie: 'anotherCookieAuth',
                requestDecoratorName: 'anotherCookieAuth',
                password: 'password-should-be-32-characters'
            };
            server.auth.strategy('notDefault', 'cookie', options);
        }).to.not.throw();
    });

});
