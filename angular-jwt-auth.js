
(function () {
  'use strict';

  angular.module('angular-jwt-auth.credentials', [])
  .provider('credentialsService', function() {

    this.retrieve = function() {
      return null;
    };

    this.saveToken = function(token) {
      return;
    }

    this.removeToken = function(token) {
      return;
    }

    this.$get = function() {
      return {
        retrieve: this.retrieve,
        saveToken: this.saveToken,
        removeToken: this.removeToken
      }
    };

  });

  angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.credentials'])
  .config(function($httpProvider, jwtInterceptorProvider, credentialsServiceProvider) {

    jwtInterceptorProvider.tokenGetter = ['localStorageService', function(localStorageService) {
      return localStorageService.get('auth.jwt_token');
    }];

    $httpProvider.interceptors.push('jwtInterceptor');

    credentialsServiceProvider.retrieve = ['localStorageService', function(localStorageService) {
      return {
        username: localStorageService.get('auth.username'),
        password: localStorageService.get('auth.password')
      }
    }];

    credentialsServiceProvider.saveToken = ['localStorageService', function(localStorageService) {
      localStorageService.set('auth.jwt_token', this); // this is set by $injector, https://docs.angularjs.org/api/auto/service/$injector
    }];

    credentialsServiceProvider.removeToken = ['localStorageService', function(localStorageService) {
      localStorageService.remove('auth.jwt_token');
    }];

  })

  .run(function($injector, $rootScope, AuthResourceService, authService, credentialsService, jwtInterceptor) {

    $rootScope.$on('event:auth-loginRequired', function(rejection) {

      var credentials = $injector.invoke(credentialsService.retrieve);

      if (credentials === null) {
        return config;
      }

      AuthResourceService.login({_username: credentials.username, _password: credentials.password}).$promise.then(function(data) {

        var token = data.token

        // Add Authorization header to current requests
        // loginConfirmed() will dispatch an event with the token & we will save it with a listener
        authService.loginConfirmed(token, function(config) {
          config.headers.Authorization = 'Bearer ' + token;
          return config ;
        });

      }, function(error) {
        authService.loginCancelled();
      });

    });

  })

  .run(function($injector, $rootScope, credentialsService) {

    $rootScope.$on('event:auth-loginConfirmed', function(event, token) {
      $injector.invoke(credentialsService.saveToken, token);
    });

    $rootScope.$on('event:auth-loginCancelled', function(event) {
      $injector.invoke(credentialsService.removeToken);
    });

  })

})();
