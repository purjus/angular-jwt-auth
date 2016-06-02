# angular-jwt-auth
Mix [auth0/angular-jwt](https://github.com/auth0/angular-jwt) & [witoldsz/angular-http-auth](https://github.com/witoldsz/angular-http-auth) to get automatic auth when response code is 401.

## Documentation

### Installation

```sh
bower install --save azzra/angular-jwt-auth
```

### Set the login_check URL

```js
angular.module('app', ['...', 'angular-jwt-auth', 'http-auth-interceptor'])....
```

```js
// app.js
.config(function(credentialsServiceProvider) {
  credentialsServiceProvider.urlLoginCheck = '/login_check';
})
```

### Custom methods

You can override the `credentialsService` methods.

```js
angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.credentials', 'LocalStorageModule'])
.config(function($httpProvider, jwtInterceptorProvider, credentialsServiceProvider) {

  // Please note we're annotating the function so that the $injector works when the file is minified
  credentialsServiceProvider.saveToken = ['localStorageService', function(localStorageService) {
     // "this" is set by $injector, https://docs.angularjs.org/api/auto/service/$injector
    localStorageService.set('auth.jwt_token', this);
  }];

});
```
