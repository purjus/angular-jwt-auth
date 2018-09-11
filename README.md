# angular-jwt-auth-module
Mix [auth0/angular-jwt](https://github.com/auth0/angular-jwt) & [witoldsz/angular-http-auth](https://github.com/witoldsz/angular-http-auth) to get automatic auth when response code is 401.

> DEPRECATED as it's only compatible with AngularJS

> NO TESTS

---

## Documentation

### Installation

```sh
npm i angular-jwt-auth-module
```

### Build

```sh
gulp build
```

### Set the login_check URL

```js
angular.module('app', ['...', 'angular-jwt-auth-module', 'http-auth-interceptor'])....
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
angular.module('angular-jwt-auth-module', ['angular-jwt', 'angular-jwt-auth-module.tools', 'LocalStorageModule'])
.config(function($httpProvider, jwtInterceptorProvider, angularJwtAuthToolsProvider) {

  // Please note we're annotating the function so that the $injector works when the file is minified
  angularJwtAuthToolsProvider.saveToken = ['localStorageService', function(localStorageService) {
     // "this" is set by $injector, https://docs.angularjs.org/api/auto/service/$injector
    localStorageService.set('auth.jwt_token', this);
  }];

});
```
