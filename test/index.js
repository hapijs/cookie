'use strict';

// Load modules

const Code = require('code');
const Hapi = require('hapi');
const Hoek = require('hoek');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;


describe('scheme', () => {

    it('fails with no plugin options', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('default', 'cookie', true, {});
            }).to.throw(Error);

            done();
        });
    });

    it('passes with a password configured', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('default', 'cookie', true, { password: 'password-should-be-32-characters' });
            }).to.not.throw();

            done();
        });
    });

    it('passes with a password configured which is a Buffer', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('default', 'cookie', true, { password: new Buffer('foobar') });
            }).to.not.throw();

            done();
        });
    });

    it('fails if validateFunc is not a function', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('default', 'cookie', true, { validateFunc: 'not a function' });
            }).to.throw(Error);

            done();
        });
    });

    it('fails if keepAlive is configured but not ttl', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            expect(() => {

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    keepAlive: true
                });
            }).to.throw(Error);

            done();
        });
    });

    it('authenticates a request', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    expect(request.auth.credentials.something).to.equal('new');
                    return reply('resource');
                }
            });

            server.inject('/login/valid', (res) => {

                expect(res.result).to.equal('valid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    expect(res2.headers['set-cookie']).to.not.exist();
                    expect(res2.result).to.equal('resource');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('fails over to another strategy if not present', (done) => {

        const extraSchemePlugin = function (plugin, options, next) {

            const simpleTestSchema = function () {

                return {
                    authenticate: function (request, reply) {

                        return reply.continue({ credentials: { test: 'valid' } });
                    }
                };
            };

            plugin.auth.scheme('simpleTest', simpleTestSchema);
            return next();
        };

        extraSchemePlugin.attributes = {
            name: 'simpleTestAuth'
        };

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.register(extraSchemePlugin, (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('simple', 'simpleTest');

                server.route({
                    method: 'GET',
                    path: '/multiple',
                    config: {
                        auth: {
                            mode: 'try',
                            strategies: ['default', 'simple']
                        },
                        handler: function (request, reply) {

                            const credentialsTest = (request.auth.credentials && request.auth.credentials.test) || 'NOT AUTH';
                            return reply('multiple ' + credentialsTest);
                        }
                    }
                });

                server.inject('/multiple', (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('multiple valid');
                    done();
                });
            });
        });
    });

    it('ends a session', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/logout', handler: function (request, reply) {

                    request.cookieAuth.clear();
                    return reply('logged-out');
                }
            });

            server.inject('/login/valid', (res) => {

                expect(res.result).to.equal('valid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/logout', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    expect(res2.result).to.equal('logged-out');
                    expect(res2.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Domain=example.com; Path=/');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('fails a request with invalid session', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    expect(request.auth.credentials.something).to.equal('new');
                    return reply('resource');
                }
            });

            server.inject('/login/invalid', (res) => {

                expect(res.result).to.equal('invalid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Domain=example.com; Path=/');
                    expect(res2.statusCode).to.equal(401);
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('does not clear a request with invalid session (clearInvalid not set)', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    expect(request.auth.credentials.something).to.equal('new');
                    return reply('resource');
                }
            });

            server.inject('/login/invalid', (res) => {

                expect(res.result).to.equal('invalid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.headers['set-cookie']).to.not.exist();
                    expect(res2.statusCode).to.equal(401);
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('logs in and authenticates a request', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    expect(request.auth.credentials.user).to.equal('steve');
                    return reply('resource');
                }
            });

            server.inject('/login/steve', (res) => {

                expect(res.result).to.equal('steve');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    expect(res2.result).to.equal('resource');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('errors in validation function', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    return callback(new Error('boom'));
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    expect(request.auth.credentials.user).to.equal('steve');
                    return reply('resource');
                }
            });

            /* eslint-disable hapi/no-shadow-relaxed */
            server.inject('/login/steve', (res) => {

                expect(res.result).to.equal('steve');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(401);
                    done();
                });
            });
            /* eslint-enable hapi/no-shadow-relaxed */
        });
    });

    it('authenticates a request (no ttl)', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.inject('/login/valid', (res) => {

                expect(res.result).to.equal('valid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.not.contain('Max-Age');
                done();
            });
        });
    });

    it('authenticates a request (no session override)', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                path: '/example-path',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    return callback(null, session.user === 'valid');
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    return reply('resource');
                }
            });

            server.inject('/login/valid', (res) => {

                expect(res.result).to.equal('valid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    expect(res2.result).to.equal('resource');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('authenticates a request (no session override) on a sub-path', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                path: '/subpath',
                clearInvalid: true,
                validateFunc: function (request, session, callback) {

                    return callback(null, session.user === 'valid');
                }
            });

            server.route({
                method: 'GET', path: '/subpath/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/subpath/resource', handler: function (request, reply) {

                    return reply('resource');
                }
            });

            server.inject('/subpath/login/valid', (res) => {

                expect(res.result).to.equal('valid');
                const header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);
                expect(header[0]).to.contain('Path=/subpath');

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/subpath/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    expect(res2.result).to.equal('resource');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('extends ttl automatically', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                keepAlive: true
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    return reply('resource');
                }
            });

            server.inject('/login/valid', (res) => {

                let header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    header = res2.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    it('extends ttl automatically (validateFunc)', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                keepAlive: true,
                validateFunc: function (request, session, callback) {

                    const override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.cookieAuth.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    expect(request.auth.credentials.something).to.equal('new');
                    return reply('resource');
                }
            });

            server.inject('/login/valid', (res) => {

                expect(res.result).to.equal('valid');
                let header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                const cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                /* eslint-disable hapi/no-shadow-relaxed */
                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                    expect(res2.statusCode).to.equal(200);
                    expect(res2.result).to.equal('resource');

                    header = res2.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    done();
                });
                /* eslint-enable hapi/no-shadow-relaxed */
            });
        });
    });

    describe('set()', () => {

        it('errors on missing session in set()', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.set();
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('Invalid session');
                    done();
                });
            });
        });

        it('sets individual cookie key', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            request.cookieAuth.set({ user: request.params.user });
                            return reply(request.params.user);
                        }
                    }
                });

                server.route({
                    method: 'GET', path: '/setKey', handler: function (request, reply) {

                        request.cookieAuth.set('key', 'value');
                        done();
                    }
                });

                server.inject('/login/steve', (res) => {

                    const pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
                    expect(res.result).to.equal('steve');
                    const header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    const cookie = header[0].match(pattern);

                    /* eslint-disable hapi/no-shadow-relaxed */
                    server.inject({ method: 'GET', url: '/setKey', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                        expect(res2.statusCode).to.equal(200);
                    });
                    /* eslint-enable hapi/no-shadow-relaxed */
                });
            });
        });

        it('throws on missing session when trying to set key', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.set('key', 'value');
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('No active session to apply key to');
                    done();
                });
            });
        });

        it('throws when trying to set key with invalid input', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.set({}, 'value');
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });

        it('throws when trying to set key with null key', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.set(null, 'value');
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });
    });

    describe('clear()', () => {

        it('clear a specific session key', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            request.cookieAuth.set({ user: request.params.user });
                            return reply(request.params.user);
                        }
                    }
                });

                server.route({
                    method: 'GET', path: '/clearKey', handler: function (request, reply) {

                        request.cookieAuth.clear('key');
                        done();
                    }
                });

                server.inject('/login/steve', (res) => {

                    const pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
                    expect(res.result).to.equal('steve');
                    const header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    const cookie = header[0].match(pattern);

                    /* eslint-disable hapi/no-shadow-relaxed */
                    server.inject({ method: 'GET', url: '/clearKey', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                        expect(res2.statusCode).to.equal(200);
                    });
                    /* eslint-enable hapi/no-shadow-relaxed */
                });
            });
        });

        it('throws when trying to clear a key on missing session', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.clear('key');
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('No active session to clear key from');
                    done();
                });
            });
        });

        it('throws when trying to clear a key with invalid input', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.clear({});
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });

        it('throws when trying to clear a key with null input', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            try {
                                request.cookieAuth.clear(null);
                            }
                            catch (error) {
                                return reply(error.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', (res) => {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });
    });

    describe('ttl()', () => {

        it('overrides ttl', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            request.cookieAuth.set({ user: request.params.user });
                            request.cookieAuth.ttl(60 * 1000);
                            return reply(request.params.user);
                        }
                    }
                });

                server.route({
                    method: 'GET', path: '/ttl', handler: function (request, reply) {

                        request.cookieAuth.set('key', 'value');
                        done();
                    }
                });

                server.inject('/login/steve', (res) => {

                    const pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
                    expect(res.result).to.equal('steve');
                    const header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    const cookie = header[0].match(pattern);

                    /* eslint-disable hapi/no-shadow-relaxed */
                    server.inject({ method: 'GET', url: '/ttl', headers: { cookie: 'special=' + cookie[1] } }, (res2) => {

                        expect(res2.statusCode).to.equal(200);
                    });
                    /* eslint-enable hapi/no-shadow-relaxed */
                });
            });
        });
    });

    describe('redirection', () => {

        it('sends to login page (uri without query)', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?next=%2F');
                    done();
                });
            });
        });

        it('skips when redirectTo is set to false', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: false,
                    appendNext: true
                });

                server.route({
                    method: 'GET',
                    path: '/',
                    handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });

        it('skips when route override', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET',
                    path: '/',
                    handler: function (request, reply) {

                        return reply('never');
                    },
                    config: {
                        plugins: {
                            'hapi-auth-cookie': {
                                redirectTo: false
                            }
                        }
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });

        it('skips when redirectOnTry is false in try mode', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', 'try', {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectOnTry: false,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET',
                    path: '/',
                    handler: function (request, reply) {

                        return reply(request.auth.isAuthenticated);
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal(false);
                    done();
                });
            });
        });

        it('sends to login page (uri with query)', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1&next=%2F');
                    done();
                });
            });
        });

        it('sends to login page and does not append the next query when appendNext is false', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: false
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1');
                    done();
                });
            });
        });

        it('appends the custom query when appendNext is string', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: 'done'
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1&done=%2F');
                    done();
                });
            });
        });

        it('redirect on try', (done) => {

            const server = new Hapi.Server();
            server.connection();
            server.register(require('../'), (err) => {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password-should-be-32-characters',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', config: { auth: { mode: 'try' } }, handler: function (request, reply) {

                        return reply('try');
                    }
                });

                server.inject('/', (res) => {

                    expect(res.statusCode).to.equal(302);
                    done();
                });
            });
        });
    });

    it('clear cookie on invalid', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password-should-be-32-characters',
                ttl: 60 * 1000,
                clearInvalid: true
            });

            server.route({
                method: 'GET', path: '/', handler: function (request, reply) {

                    return reply();
                }
            });

            server.inject({ url: '/', headers: { cookie: 'sid=123456' } }, (res) => {

                expect(res.statusCode).to.equal(401);
                expect(res.headers['set-cookie'][0]).to.equal('sid=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Path=/');
                done();
            });
        });
    });

    it('supports many strategies', (done) => {

        const server = new Hapi.Server();
        server.connection();
        server.register(require('../'), (err) => {

            expect(err).to.not.exist();

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

            done();
        });
    });
});
