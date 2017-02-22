# angular-jwt-auth
Mix [auth0/angular-jwt](https://github.com/auth0/angular-jwt) & [witoldsz/angular-http-auth](https://github.com/witoldsz/angular-http-auth) to get automatic auth when response code is 401.

## Documentation

### Installation

```sh
bower install --save azzra/angular-jwt-auth
```

### Build

```sh
gulp build
```

### Set the login_check URL

```js
angular.module('app', ['...', 'angular-jwt-auth', 'http-auth-interceptor'])....
```

```js
// app.js
.config(function(angularJwtAuthToolsProvider) {
  angularJwtAuthToolsProvider.urlLoginCheck = '/login_check';
})
```

### Custom methods

You can override the `angularJwtAuthTools` methods.

```js
angular.module('angular-jwt-auth', ['angular-jwt', 'angular-jwt-auth.tools', 'LocalStorageModule'])
.config(function($httpProvider, jwtInterceptorProvider, angularJwtAuthToolsProvider) {

  // Please note we're annotating the function so that the $injector works when the file is minified
  angularJwtAuthToolsProvider.saveToken = ['localStorageService', function(localStorageService) {
     // "this" is set by $injector, https://docs.angularjs.org/api/auto/service/$injector
    localStorageService.set('auth.jwt_token', this);
  }];

});
```
