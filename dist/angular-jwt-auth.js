(function() {

angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.credentials', 'angular-ws-service', 'LocalStorageModule'])
.config(["$httpProvider", "jwtInterceptorProvider", "credentialsServiceProvider", function($httpProvider, jwtInterceptorProvider, credentialsServiceProvider) {

    jwtInterceptorProvider.tokenGetter = ['$injector', 'options', 'jwtHelper', '$http', 'WsService', function($injector, options, jwtHelper, $http, WsService) {

        if ('.html' === options.url.substr(options.url.length - 5)) {
            return null;
        }

        var existingToken = $injector.invoke(credentialsServiceProvider.existingTokenRetriever);

        // We got a expired token
        if (existingToken.token !== null && jwtHelper.isTokenExpired(existingToken.token)) {

            // This is a promise of a JWT token
            return $http({
                url: credentialsServiceProvider.urlTokenRefresh,
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
                $injector.invoke(credentialsServiceProvider.tokenSaver, data);
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

.run(["$injector", "$rootScope", "authService", "credentialsService", function($injector, $rootScope, authService, credentialsService) {

    $rootScope.$on('event:auth-loginRequired', function() {

        var credentials = $injector.invoke(credentialsService.credentialsRetriever);

        if (credentials === null) {
            authService.loginCancelled();
            return;
        }

        $injector.invoke(credentialsService.tokenRetriever, {_username: credentials.username, _password: credentials.password}).then(function(response) {

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

.run(["$injector", "$rootScope", "credentialsService", function($injector, $rootScope, credentialsService) {

    $rootScope.$on('event:auth-loginConfirmed', function(event, token) {
        $injector.invoke(credentialsService.tokenSaver, token);
    });

    $rootScope.$on('event:auth-loginCancelled', function() {
        $injector.invoke(credentialsService.tokenRemover);
    });

}]);

angular.module('angular-jwt-auth.credentials', [])
.provider('credentialsService', function() {

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

.config(["credentialsServiceProvider", function(credentialsServiceProvider) {

    credentialsServiceProvider.credentialsRetriever = ['localStorageService', function(localStorageService) {

        if (localStorage.getItem('auth.username') === null || localStorage.getItem('auth.password') === null) {
            return null;
        }

        return {
            username: localStorageService.get('auth.username'),
            password: localStorageService.get('auth.password')
        };
    }];

    credentialsServiceProvider.tokenSaver = ['localStorageService', function(localStorageService) {
        localStorageService.set('auth.jwt_token', this.token);
        localStorageService.set('auth.jwt_refresh_token', this.refresh_token);
    }];

    credentialsServiceProvider.existingTokenRetriever = ['localStorageService', function(localStorageService) {
        return {
            token: localStorageService.get('auth.jwt_token'),
            refreshToken: localStorageService.get('auth.jwt_refresh_token')
        };
    }];

    credentialsServiceProvider.tokenRemover = ['localStorageService', function(localStorageService) {
        localStorageService.remove('auth.jwt_token', 'auth.jwt_refresh_token');
    }];

    credentialsServiceProvider.tokenRetriever = ['$http', 'WsService', function($http, WsService) {
        // We don't send Authorization headers
        return $http.post(credentialsServiceProvider.urlLoginCheck, this, {ignoreAuthModule: true, skipAuthorization: true, headers: {'Content-Type': 'application/x-www-form-urlencoded'}, transformRequest: WsService.objectToURLEncoded});
    }];

}]);

}());
