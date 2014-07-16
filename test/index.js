// Load modules

var Lab = require('lab');
var Hapi = require('hapi');
var Hoek = require('hoek');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


describe('Cookie', function () {

    var server = new Hapi.Server();
    before(function (done) {

        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

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

            server.route({
                method: 'GET', path: '/logout', handler: function (request, reply) {

                    request.auth.session.clear();
                    return reply('logged-out');
                }
            });

            done();
        });
    });

    it('authenticates a request', function (done) {

        server.inject('/login/valid', function (res) {

            expect(res.result).to.equal('valid');
            var header = res.headers['set-cookie'];
            expect(header.length).to.equal(1);
            expect(header[0]).to.contain('Max-Age=60');
            var cookie = header[0].match(/(?:[^\x00-\x20\(\)<>@\,;\:\\"\/\[\]\?\=\{\}\x7F]+)\s*=\s*(?:([^\x00-\x20\"\,\;\\\x7F]*))/);

            server.inject({ method: 'GET', url: '/resource', headers: { cookie: 'special=' + cookie[1] } }, function (res) {

                expect(res.statusCode).to.equal(200);
                expect(res.headers['set-cookie']).to.not.exist;
                expect(res.result).to.equal('resource');
                done();
            });
        });
    });

    it('ends a session', function (done) {

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

    it('fails a request with invalid session', function (done) {

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

    it('does not clear a request with invalid session', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

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

                    expect(res.headers['set-cookie']).to.not.exist;
                    expect(res.statusCode).to.equal(401);
                    done();
                });
            });
        });
    });

    it('logs in and authenticates a request', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

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
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

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
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

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
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

            server.auth.strategy('default', 'cookie', true, {
                password: 'password',
                ttl: 60 * 1000,
                domain: 'example.com',
                cookie: 'special',
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

    it('errors on missing session in set()', function (done) {

        var server = new Hapi.Server();
        server.pack.register(require('../'), function (err) {

            expect(err).to.not.exist;

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

    describe('redirection', function (done) {

        it('sends to login page (uri without query)', function (done) {

            var server = new Hapi.Server();
            server.pack.register(require('../'), function (err) {

                expect(err).to.not.exist;

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

        it('skips when route override', function (done) {

            var server = new Hapi.Server();
            server.pack.register(require('../'), function (err) {

                expect(err).to.not.exist;

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
            server.pack.register(require('../'), function (err) {

                expect(err).to.not.exist;

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
            server.pack.register(require('../'), function (err) {

                expect(err).to.not.exist;

                server.auth.strategy('default', 'cookie',true,  {
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
            server.pack.register(require('../'), function (err) {

                expect(err).to.not.exist;

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

        it('redirect on try', function (done) {

            var server = new Hapi.Server();
            server.pack.register(require('../'), function (err) {

                expect(err).to.not.exist;

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
});
