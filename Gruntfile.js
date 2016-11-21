'use strict';

module.exports = function(grunt) {

    grunt.loadNpmTasks('grunt-eslint');
    grunt.loadNpmTasks('grunt-version-check');

    // Project configuration.
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        eslint: {
            src: {
                src: ['*.js' ]
            },
            test: {
                src: ['tests/**/*.js'],
            }
        },
        versioncheck: {
            target: {
                options: {
                    skip : ['semver', 'npm'],
                    hideUpToDate : false
                }
            }
        },
    });

    grunt.registerTask('lint', ['eslint']);
    grunt.registerTask('default', ['eslint']);
};
