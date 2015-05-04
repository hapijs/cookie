// Load modules

var Code = require('code');
var Hapi = require('hapi');
var Hoek = require('hoek');
var Lab = require('lab');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;


describe('scheme', function () {
    it('fails with no plugin options', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function(err) {
            expect(err).to.not.exist();

            expect( function () {
                server.auth.strategy('default', 'cookie', true, {});
            } ).to.throw(Error);

            done();
        });
    });

    it('passes with a password configured', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function(err) {
            expect(err).to.not.exist();

            expect( function () {
                server.auth.strategy('default', 'cookie', true, {
                    password: 'password'
                });
            } ).to.not.throw();

            done();
        });
    });

    it('fails if validateFunc is not a function', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function(err) {
            expect(err).to.not.exist();

            expect( function () {
                server.auth.strategy('default', 'cookie', true, {
                    validateFunc: 'not a function'
                });
            } ).to.throw(Error);

            done();
        });
    });

    it('fails if keepAlive is configured but not ttl', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function(err) {
            expect(err).to.not.exist();

            expect( function () {
                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    keepAlive: true
                });
            } ).to.throw(Error);

            done();
        });
    });

    it('authenticates a request', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
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

            server.inject('/login/valid', function (res) {

                expect(res.result).to.equal('valid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.headers['set-cookie']).to.not.exist();
                    expect(res.result).to.equal('resource');
                    done();
                });
            });
        });
    });

    it('fails over to another strategy if not present', function (done) {

        var extraSchemePlugin = function (plugin, options, next) {

            var simpleTestSchema = function () {

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

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.register(extraSchemePlugin, function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('simple', 'simpleTest');

                server.route({
                    method: 'GET',
                    path: '/multiple',
                    config: {
                        auth: {
                            mode: 'try',
                            strategies: ['default', 'simple'],
                        },
                        handler: function (request, reply) {

                            var credentialsTest = (request.auth.credentials && request.auth.credentials.test) || 'NOT AUTH';
                            return reply('multiple ' + credentialsTest);
                        }
                    }
                });

                server.inject('/multiple', function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('multiple valid');
                    done();
                });
            });
        });
    });

    it('ends a session', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/logout', handler: function (request, reply) {

                    request.auth.session.clear();
                    return reply('logged-out');
                }
            });

            server.inject('/login/valid', function (res) {

                expect(res.result).to.equal('valid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/logout', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('logged-out');
                    expect(res.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Domain=example.com; Path=/');
                    done();
                });
            });
        });
    });

    it('fails a request with invalid session', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
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

            server.inject('/login/invalid', function (res) {

                expect(res.result).to.equal('invalid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Domain=example.com; Path=/');
                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });
    });

    it('does not clear a request with invalid session (clearInvalid not set)', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
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

            server.inject('/login/invalid', function (res) {

                expect(res.result).to.equal('invalid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.headers['set-cookie']).to.not.exist();
                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });
    });

    it('logs in and authenticates a request', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
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

            server.inject('/login/steve', function (res) {

                expect(res.result).to.equal('steve');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('resource');
                    done();
                });
            });
        });
    });

    it('errors in validation function', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) { return callback(new Error('boom')); }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
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

            server.inject('/login/steve', function (res) {

                expect(res.result).to.equal('steve');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });
    });

    it('authenticates a request (no ttl)', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.inject('/login/valid', function (res) {

                expect(res.result).to.equal('valid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.not.contain('Max-Age');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);
                done();
            });
        });
    });

    it('authenticates a request (no session override)', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                path: '/example-path',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    return callback(null, session.user === 'valid');
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    return reply('resource');
                }
            });

            server.inject('/login/valid', function (res) {

                expect(res.result).to.equal('valid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('resource');
                    done();
                });
            });
        });
    });

    it('authenticates a request (no session override) on a sub-path', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                path: '/subpath',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    return callback(null, session.user === 'valid');
                }
            });

            server.route({
                method: 'GET', path: '/subpath/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/subpath/resource', handler: function (request, reply) {

                    return reply('resource');
                }
            });

            server.inject('/subpath/login/valid', function (res) {

                expect(res.result).to.equal('valid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);
                expect(header[0]).to.contain('Path=/subpath');

                server.inject({ method: 'GET', url: '/subpath/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('resource');
                    done();
                });
            });
        });
    });

    it('extends ttl automatically', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
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

                        request.auth.session.set({ user: request.params.user });
                        return reply(request.params.user);
                    }
                }
            });

            server.route({
                method: 'GET', path: '/resource', handler: function (request, reply) {

                    return reply('resource');
                }
            });

            server.inject('/login/valid', function (res) {

                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    var header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    done();
                });
            });
        });
    });

    it('extends ttl automatically (validateFunc)', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
                clearInvalid: true,
                keepAlive: true,
                validateFunc: function (session, callback) {

                    var override = Hoek.clone(session);
                    override.something = 'new';

                    return callback(null, session.user === 'valid', override);
                }
            });

            server.route({
                method: 'GET', path: '/login/{user}',
                config: {
                    auth: { mode: 'try' },
                    handler: function (request, reply) {

                        request.auth.session.set({ user: request.params.user });
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

            server.inject('/login/valid', function (res) {

                expect(res.result).to.equal('valid');
                var header = res.headers['set-cookie'];
                expect(header.length).to.equal(1);
                expect(header[0]).to.contain('Max-Age=60');
                var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

                server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal('resource');

                    var header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    done();
                });
            });
        });
    });

    describe('set()', function () {

        it('errors on missing session in set()', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.set();
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('Invalid session');
                    done();
                });
            });
        });

        it('sets individual cookie key', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            request.auth.session.set({ user: request.params.user });
                            return reply(request.params.user);
                        }
                    }
                });

                server.route({
                    method: 'GET', path: '/setKey', handler: function (request, reply) {
                        request.auth.session.set('key', 'value');
                        done();
                    }
                });

                server.inject('/login/steve', function (res) {
                    var pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
                    expect(res.result).to.equal('steve');
                    var header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    var cookie = header[0].match(pattern);

                    server.inject({ method: 'GET', url: '/setKey', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                        expect(res.statusCode).to.equal(200);
                    });
                });
            });
        });

        it('throws on missing session when trying to set key', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.set('key', 'value');
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('No active session to apply key to');
                    done();
                });
            });
        });

        it('throws when trying to set key with invalid input', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.set({}, 'value');
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });

        it('throws when trying to set key with null key', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.set(null, 'value');
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });
    });

    describe('clear()', function () {

        it('clear a specific session key', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            request.auth.session.set({ user: request.params.user });
                            return reply(request.params.user);
                        }
                    }
                });

                server.route({
                    method: 'GET', path: '/clearKey', handler: function (request, reply) {
                        request.auth.session.clear('key');
                        done();
                    }
                });

                server.inject('/login/steve', function (res) {
                    var pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
                    expect(res.result).to.equal('steve');
                    var header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    var cookie = header[0].match(pattern);

                    server.inject({ method: 'GET', url: '/clearKey', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                        expect(res.statusCode).to.equal(200);
                    });
                });
            });
        });

        it('throws when trying to clear a key on missing session', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.clear('key');
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('No active session to clear key from');
                    done();
                });
            });
        });

        it('throws when trying to clear a key with invalid input', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.clear({});
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });

        it('throws when trying to clear a key with null input', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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
                                request.auth.session.clear(null);
                            }
                            catch (err) {
                                return reply(err.message);
                            }

                            return reply('ok');
                        }
                    }
                });

                server.inject('/login/steve', function (res) {

                    expect(res.result).to.equal('Invalid session key');
                    done();
                });
            });
        });
    });

    describe('ttl()', function () {

        it('overrides ttl', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 1000,
                    cookie: 'special',
                    clearInvalid: true
                });

                server.route({
                    method: 'GET', path: '/login/{user}',
                    config: {
                        auth: { mode: 'try' },
                        handler: function (request, reply) {

                            request.auth.session.set({ user: request.params.user });
                            request.auth.session.ttl(60 * 1000);
                            return reply(request.params.user);
                        }
                    }
                });

                server.route({
                    method: 'GET', path: '/ttl', handler: function (request, reply) {
                        request.auth.session.set('key', 'value');
                        done();
                    }
                });

                server.inject('/login/steve', function (res) {
                    var pattern = /(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/;
                    expect(res.result).to.equal('steve');
                    var header = res.headers['set-cookie'];
                    expect(header.length).to.equal(1);
                    expect(header[0]).to.contain('Max-Age=60');
                    var cookie = header[0].match(pattern);

                    server.inject({ method: 'GET', url: '/ttl', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                        expect(res.statusCode).to.equal(200);
                    });
                });
            });
        });
    });

    describe('redirection', function () {

        it('sends to login page (uri without query)', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?next=%2F');
                    done();
                });
            });
        });

        it('skips when redirectTo is set to false', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });

        it('skips when route override', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
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

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });

        it('skips when redirectOnTry is false in try mode', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', 'try', {
                    password: 'password',
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

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(200);
                    expect(res.result).to.equal(false);
                    done();
                });
            });
        });

        it('sends to login page (uri with query)', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1&next=%2F');
                    done();
                });
            });
        });

        it('sends to login page and does not append the next query when appendNext is false', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: false
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1');
                    done();
                });
            });
        });

        it('appends the custom query when appendNext is string', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: 'done'
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1&done=%2F');
                    done();
                });
            });
        });

        it('redirect on try', function (done) {

            var server = new Hapi.Server();
            server.connection();
            server.register(require('../'), function (err) {

                expect(err).to.not.exist();

                server.auth.strategy('default', 'cookie', true, {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', config: { auth: { mode: 'try' } }, handler: function (request, reply) {

                        return reply('try');
                    }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    done();
                });
            });
        });
    });

    it('clear cookie on invalid', function (done) {

        var server = new Hapi.Server();
        server.connection();
        server.register(require('../'), function (err) {

            expect(err).to.not.exist();

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                clearInvalid: true
            });

            server.route({ method: 'GET', path: '/', handler: function (request, reply) { return reply(); } });

            server.inject({ url: '/', headers: { cookie: 'sid=123456' } }, function (res) {

                expect(res.statusCode).to.equal(401);
                expect(res.headers['set-cookie'][0]).to.equal('sid=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Path=/');
                done();
            });
        });
    });
});
