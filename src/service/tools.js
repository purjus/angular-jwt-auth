angular.module('angular-jwt-auth-module.tools', [])
.provider('angularJwtAuthTools', function() {

    this.urlLoginCheck = '/login_check';
    this.urlTokenRefresh = '/token/refresh';
    this.prefix = 'rrg.';

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

.config(function(angularJwtAuthToolsProvider) {

    angularJwtAuthToolsProvider.tokenSaver = function() {
        console.log("tokenSaverinvoke");
        localStorage.setItem(this.prefix + 'auth.jwt_token', this.token);
        localStorage.setItem(this.prefix + 'auth.jwt_refresh_token', this.refresh_token);
    };

    angularJwtAuthToolsProvider.existingTokenRetriever = function() {
        console.log("existingtokeninvoke");
        return {
            token: localStorage.getItem(this.prefix + 'auth.jwt_token'),
            refreshToken: localStorage.getItem(this.prefix + 'auth.jwt_refresh_token')
        };
    };

    angularJwtAuthToolsProvider.tokenRemover = function() {
        localStorage.removeItem(this.prefix + 'auth.jwt_token');
        localStorage.removeItem(this.prefix + 'auth.jwt_refresh_token');
    };

    angularJwtAuthToolsProvider.tokenRetriever = ['$http', 'WsService', function($http, WsService) {
        // We don't send Authorization headers
        return $http.post(angularJwtAuthToolsProvider.urlLoginCheck, this, {ignoreAuthModule: true, skipAuthorization: true, headers: {'Content-Type': 'application/x-www-form-urlencoded'}, transformRequest: WsService.objectToURLEncoded});
    }];

});
