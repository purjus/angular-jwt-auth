(function() {

angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.tools', 'angular-ws-service', 'LocalStorageModule'])
.config(["$httpProvider", "jwtInterceptorProvider", "angularJwtAuthToolsProvider", function($httpProvider, jwtInterceptorProvider, angularJwtAuthToolsProvider) {

    jwtInterceptorProvider.tokenGetter = ['$injector', 'options', 'jwtHelper', '$http', 'WsService', function($injector, options, jwtHelper, $http, WsService) {

        if (Array.isArray(angularJwtAuthToolsProvider.ignoredUrlExtensions) && angularJwtAuthToolsProvider.ignoredUrlExtensions.length) {
            var splitUrl = options.url.split('.');
            if (-1 !== angularJwtAuthToolsProvider.ignoredUrlExtensions.indexOf(splitUrl.pop())) {
                return null;
            }

        }

        var existingToken = $injector.invoke(angularJwtAuthToolsProvider.existingTokenRetriever);

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

}])

.run(["$injector", "$rootScope", "authService", "angularJwtAuthTools", function($injector, $rootScope, authService, angularJwtAuthTools) {

    $rootScope.$on('event:auth-loginRequired', function() {

        var credentials = $injector.invoke(angularJwtAuthTools.credentialsRetriever);

        if (credentials === null) {
            authService.loginCancelled();
            return;
        }

        $injector.invoke(angularJwtAuthTools.tokenRetriever, {_username: credentials.username, _password: credentials.password}).then(function(response) {

            var data = response.data;

            // Add Authorization header to current requests
            authService.loginConfirmed(data, function(config) {
                config.headers.Authorization = 'Bearer ' + data.token;
                return config ;
            });

        }, function() {
            authService.loginCancelled();
        });

    });

}])

.run(["$injector", "$rootScope", "angularJwtAuthTools", function($injector, $rootScope, angularJwtAuthTools) {

    $rootScope.$on('event:auth-loginConfirmed', function(event, token) {
        $injector.invoke(angularJwtAuthTools.tokenSaver, token);
    });

    $rootScope.$on('event:auth-loginCancelled', function() {
        $injector.invoke(angularJwtAuthTools.tokenRemover);
    });

}]);

angular.module('angular-jwt-auth.tools', [])
.provider('angularJwtAuthTools', function() {

    this.urlLoginCheck = '/login_check';
    this.urlTokenRefresh = '/token/refresh';

    /**
     * Get the login & password.
     *
     * @return object
     */
    this.credentialsRetriever = function() { };


    /**
     * Get the current local tokens.
     *
     * @return object
     */
    this.existingTokenRetriever = function() { };

    /**
     * Ask for a new token at the server.
     *
     * @return object
     */
    this.tokenRetriever = function() { };

    /**
     * Save the tokens locally.
     *
     * @param object tokens
     */
    this.tokenSaver = function() { };

    /**
     * Remove the tokens.
     *
     * @return object
     */
    this.tokenRemover = function() { };

    this.$get = function() {
        return {
            credentialsRetriever: this.credentialsRetriever,
            tokenRetriever: this.tokenRetriever,
            existingTokenRetriever: this.existingTokenRetriever,
            tokenSaver: this.tokenSaver,
            tokenRemover: this.tokenRemover
        };
    };

})

.config(["angularJwtAuthToolsProvider", function(angularJwtAuthToolsProvider) {

    angularJwtAuthToolsProvider.credentialsRetriever = ['localStorageService', function(localStorageService) {

        if (localStorage.getItem('auth.username') === null || localStorage.getItem('auth.password') === null) {
            return null;
        }

        return {
            username: localStorageService.get('auth.username'),
            password: localStorageService.get('auth.password')
        };
    }];

    angularJwtAuthToolsProvider.tokenSaver = ['localStorageService', function(localStorageService) {
        localStorageService.set('auth.jwt_token', this.token);
        localStorageService.set('auth.jwt_refresh_token', this.refresh_token);
    }];

    angularJwtAuthToolsProvider.existingTokenRetriever = ['localStorageService', function(localStorageService) {
        return {
            token: localStorageService.get('auth.jwt_token'),
            refreshToken: localStorageService.get('auth.jwt_refresh_token')
        };
    }];

    angularJwtAuthToolsProvider.tokenRemover = ['localStorageService', function(localStorageService) {
        localStorageService.remove('auth.jwt_token', 'auth.jwt_refresh_token');
    }];

    angularJwtAuthToolsProvider.tokenRetriever = ['$http', 'WsService', function($http, WsService) {
        // We don't send Authorization headers
        return $http.post(angularJwtAuthToolsProvider.urlLoginCheck, this, {ignoreAuthModule: true, skipAuthorization: true, headers: {'Content-Type': 'application/x-www-form-urlencoded'}, transformRequest: WsService.objectToURLEncoded});
    }];

}]);

}());
