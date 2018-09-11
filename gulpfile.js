var gulp = require('gulp'),
  concat = require('gulp-concat'),
  uglify = require('gulp-uglify'),
  rename = require('gulp-rename'),
  ngAnnotate = require('gulp-ng-annotate'),
  sourceFiles = [
    'src/angular-jwt-auth-module.prefix',
    'src/*.js',
    'src/service/*.js',
    'src/angular-jwt-auth-module.suffix'
  ];

gulp.task('build', function() {
  gulp.src(sourceFiles)
    .pipe(concat('angular-jwt-auth-module.js'))
    .pipe(ngAnnotate())
    .pipe(gulp.dest('./dist/'))
    .pipe(uglify())
    .pipe(rename('angular-jwt-auth-module.min.js'))
    .pipe(gulp.dest('./dist'))
});


gulp.task('default', ['build']);
