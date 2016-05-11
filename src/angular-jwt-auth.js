angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.credentials', 'angular-ws-service', 'LocalStorageModule'])
.config(function($httpProvider, jwtInterceptorProvider, credentialsServiceProvider) {

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
      return token;
    }

  }];

  $httpProvider.interceptors.push('jwtInterceptor');

})

.run(function($injector, $rootScope, authService, credentialsService, jwtInterceptor) {

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

})

.run(function($injector, $rootScope, credentialsService) {

  $rootScope.$on('event:auth-loginConfirmed', function(event, token) {
    $injector.invoke(credentialsService.tokenSaver, token);
  });

  $rootScope.$on('event:auth-loginCancelled', function(event) {
    $injector.invoke(credentialsService.tokenRemover);
  });

});
