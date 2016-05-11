(function() {

angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.credentials', 'angular-ws-service', 'LocalStorageModule'])
.config(["$httpProvider", "jwtInterceptorProvider", "credentialsServiceProvider", function($httpProvider, jwtInterceptorProvider, credentialsServiceProvider) {

  jwtInterceptorProvider.tokenGetter = ['$injector', 'config', 'jwtHelper', '$http', 'localStorageService', function($injector, config, jwtHelper, $http, localStorageService) {

    if (config.url.substr(config.url.length - 5) == '.html') {
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
        ignoreAuthModule: true,
        method: 'POST',
        data: {
            refresh_token: existingToken.refreshToken
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

.run(["$injector", "$rootScope", "authService", "credentialsService", "jwtInterceptor", function($injector, $rootScope, authService, credentialsService, jwtInterceptor) {

  $rootScope.$on('event:auth-loginRequired', function(rejection) {

    var credentials = $injector.invoke(credentialsService.credentialsRetriever);

    if (credentials === null) {
      return config
    }

    $injector.invoke(credentialsService.tokenRetriever, {_username: credentials.username, _password: credentials.password}).then(function(response) {

      var data = response.data;

      // Add Authorization header to current requests
      authService.loginConfirmed(data, function(config) {
        config.headers.Authorization = 'Bearer ' + data.token;
        return config ;
      });

    }, function(error) {
      authService.loginCancelled();
    });

  });

}])

.run(["$injector", "$rootScope", "credentialsService", function($injector, $rootScope, credentialsService) {

  $rootScope.$on('event:auth-loginConfirmed', function(event, token) {
    $injector.invoke(credentialsService.tokenSaver, token);
  });

  $rootScope.$on('event:auth-loginCancelled', function(event) {
    $injector.invoke(credentialsService.tokenRemover);
  });

}]);

angular.module('angular-jwt-auth.credentials', [])
.provider('credentialsService', function() {

  this.urlLoginCheck = '/login_check';
  this.urlTokenRefresh = '/token/refresh';

  this.credentialsRetriever = function() { };

  this.existingTokenRetriever = function() { };

  this.tokenRetriever = function(credentials) { };

  this.tokenSaver = function(token) { };

  this.tokenRemover = function(token) { };

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
      localStorageService.remove('auth.jwt_token', 'auth.refresh_token');
    }];

    credentialsServiceProvider.tokenRetriever = ['$http', 'WsService', function($http, WsService) {
      // We don't send Authorization headers
      return $http.post(credentialsServiceProvider.urlLoginCheck, this, {ignoreAuthModule: true, skipAuthorization: true, headers: {'Content-Type': 'application/x-www-form-urlencoded'}, transformRequest: WsService.objectToURLEncoded});
    }];

}]);

}());
