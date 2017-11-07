'use strict';

exports.loginWithResourceEndpoint = (server) => {

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
        method: 'GET', path: '/resource', handler: function (request, h) {

            return h.response('resource');
        }
    });
};
