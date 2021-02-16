angular.module('angular-jwt-auth-module', ['angular-jwt', 'angular-jwt-auth-module.tools', 'angular-ws-service'])
    .config(function($httpProvider, jwtInterceptorProvider, angularJwtAuthToolsProvider) {

        jwtInterceptorProvider.tokenGetter = ['$injector', 'options', 'jwtHelper', '$http', 'WsService', function($injector, options, jwtHelper, $http, WsService) {

            if (Array.isArray(angularJwtAuthToolsProvider.ignoredUrlExtensions) && angularJwtAuthToolsProvider.ignoredUrlExtensions.length) {
                var splitUrl = options.url.split('.');
                if (-1 !== angularJwtAuthToolsProvider.ignoredUrlExtensions.indexOf(splitUrl.pop())) {
                    return null;
                }
            }

            var existingToken = $injector.invoke(angularJwtAuthToolsProvider.existingTokenRetriever);
            console.log("existingtoken", existingToken);

            // We got a expired token
            if (existingToken.token !== null && jwtHelper.isTokenExpired(existingToken.token)) {

                // This is a promise of a JWT token
                return $http({
                    url: angularJwtAuthToolsProvider.urlTokenRefresh,
                    // This makes it so that this request doesn't send the JWT
                    skipAuthorization: true,
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    transformRequest: WsService.objectToURLEncoded,
                    ignoreAuthModule: true,
                    method: 'POST',
                    data: {
                        'refresh_token': existingToken.refreshToken
                    }
                }).then(function(response) {

                    var data = response.data;
                    console.log("new token", response.data);
                    $injector.invoke(angularJwtAuthToolsProvider.tokenSaver, data);
                    return data.token;

                }, function() {

                    // If the refresh didn't succeed (ie. refresh_token have been deleted in DB), return null so authService can work
                    return null;

                });

            } else {
                return existingToken.token;
            }

        }];

        $httpProvider.interceptors.push('jwtInterceptor');

    })

    .run(function($injector, $rootScope, angularJwtAuthTools) {

        $rootScope.$on('event:auth-loginConfirmed', function(event, token) {
            $injector.invoke(angularJwtAuthTools.tokenSaver, token);
        });

        $rootScope.$on('event:auth-loginCancelled', function() {
            $injector.invoke(angularJwtAuthTools.tokenRemover);
        });

    });
