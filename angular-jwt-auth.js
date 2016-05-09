
(function () {
  'use strict';

  angular.module('angular-jwt-auth.credentials', [])
  .provider('credentialsService', function() {

    this.credentialsRetrieve = function() { return null; };

    this.tokenRetrieve = function(credentials) { return null; };

    this.tokenSave = function(token) {};

    this.tokenRemove = function(token) {};

    this.$get = function() {
      return {
        credentialsRetrieve: this.credentialsRetrieve,
        tokenRetrieve: this.tokenRetrieve,
        tokenSave: this.tokenSave,
        tokenRemove: this.tokenRemove
      }
    };

  })

  angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.credentials', 'angular-ws-service', 'LocalStorageModule'])
  .config(function($httpProvider, jwtInterceptorProvider, credentialsServiceProvider) {

    jwtInterceptorProvider.tokenGetter = ['localStorageService', function(localStorageService) {
      return localStorageService.get('auth.jwt_token');
    }];

    $httpProvider.interceptors.push('jwtInterceptor');

    credentialsServiceProvider.credentialsRetrieve = ['localStorageService', function(localStorageService) {
      return {
        username: localStorageService.get('auth.username'),
        password: localStorageService.get('auth.password')
      }
    }];

    credentialsServiceProvider.tokenSave = ['localStorageService', function(localStorageService) {
      localStorageService.set('auth.jwt_token', this);
    }];

    credentialsServiceProvider.tokenRemove = ['localStorageService', function(localStorageService) {
      localStorageService.remove('auth.jwt_token');
    }];

    credentialsServiceProvider.tokenRetrieve = ['$http', 'WsService', function($http, WsService) {
      return $http.post(credentialsServiceProvider.urlLoginCheck, this, {ignoreAuthModule: true, headers: {'Content-Type': 'application/x-www-form-urlencoded'}, transformRequest: WsService.objectToURLEncoded});
    }];

  })

  .run(function($injector, $rootScope, authService, credentialsService, jwtInterceptor) {

    credentialsService.easyLogin = function(username, password) {
      return $injector.invoke(credentialsService.tokenRetrieve, {_username: username, _password: password});
    }

    $rootScope.$on('event:auth-loginRequired', function(rejection) {

      var credentials = $injector.invoke(credentialsService.credentialsRetrieve);

      if (credentials === null) {
        return config;
      }

      $injector.invoke(credentialsService.tokenRetrieve, {_username: credentials.username, _password: credentials.password}).then(function(response) {

        var token = response.data.token;

        // Add Authorization header to current requests
        authService.loginConfirmed(token, function(config) {
          config.headers.Authorization = 'Bearer ' + token;
          return config ;
        });

        $injector.invoke(credentialsService.tokenSave, token);

      }, function(error) {
        authService.loginCancelled();
        $injector.invoke(credentialsService.tokenRemove);
      });

    });

  })

})();
