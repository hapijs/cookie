// Load modules

var Lab = require('lab');
var Hapi = require('hapi');


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

        server.pack.require('../', function (err) {

            expect(err).to.not.exist;

            server.auth.strategy('default', 'cookie', {
                password: 'password',
                ttl: 60 * 1000,
                cookie: 'special',
                clearInvalid: true,
                validateFunc: function (session, callback) {

                    var override = Hapi.utils.clone(session);
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
                },
                config: { auth: true }
            });

            server.route({
                method: 'GET', path: '/logout', handler: function (request, reply) {

                    request.auth.session.clear();
                    return reply('logged-out');
                }, config: { auth: true }
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
                expect(res.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Path=/');
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

                expect(res.headers['set-cookie'][0]).to.equal('special=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; Path=/');
                expect(res.statusCode).to.equal(401);
                done();
            });
        });
    });

    it('authenticates a request', function (done) {

        var server = new Hapi.Server();
        server.pack.require('../', function (err) {

            expect(err).to.not.exist;

            server.auth.strategy('default', 'cookie', {
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
                },
                config: { auth: true }
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

    describe('redirection', function (done) {

        it('sends to login page (uri without query)', function (done) {

            var server = new Hapi.Server();
            server.pack.require('../', function (err) {

                expect(err).to.not.exist;

                server.auth.strategy('default', 'cookie', {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }, config: { auth: true }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?next=%2F');
                    done();
                });
            });
        });

        it('sends to login page (uri with query)', function (done) {

            var server = new Hapi.Server();
            server.pack.require('../', function (err) {

                expect(err).to.not.exist;

                server.auth.strategy('default', 'cookie', {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: true
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }, config: { auth: true }
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
            server.pack.require('../', function (err) {

                expect(err).to.not.exist;

                server.auth.strategy('default', 'cookie', {
                    password: 'password',
                    ttl: 60 * 1000,
                    redirectTo: 'http://example.com/login?mode=1',
                    appendNext: false
                });

                server.route({
                    method: 'GET', path: '/', handler: function (request, reply) {

                        return reply('never');
                    }, config: { auth: true }
                });

                server.inject('/', function (res) {

                    expect(res.statusCode).to.equal(302);
                    expect(res.headers.location).to.equal('http://example.com/login?mode=1');
                    done();
                });
            });
        });

        it('does not redirect on try', function (done) {

            var server = new Hapi.Server();
            server.pack.require('../', function (err) {

                expect(err).to.not.exist;

                server.auth.strategy('default', 'cookie', {
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

                    expect(res.result).to.equal('try');
                    expect(res.statusCode).to.equal(200);
                    done();
                });
            });
        });
    });
});
