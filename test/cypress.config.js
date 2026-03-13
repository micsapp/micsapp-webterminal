const { defineConfig } = require('cypress');

module.exports = defineConfig({
  e2e: {
    // Base URL — the nginx proxy endpoint (through Cloudflare tunnel or direct)
    baseUrl: process.env.CYPRESS_BASE_URL || 'https://micsmac-ssh.micstec.com',

    // Spec pattern
    specPattern: 'cypress/e2e/**/*.cy.{js,ts}',
    supportFile: 'cypress/support/e2e.js',

    // Timeouts
    defaultCommandTimeout: 10000,
    requestTimeout: 15000,
    responseTimeout: 30000,
    pageLoadTimeout: 60000,

    // Viewport (desktop by default)
    viewportWidth: 1280,
    viewportHeight: 800,

    // Video & screenshots
    video: true,
    screenshotOnRunFailure: true,
    screenshotsFolder: 'cypress/screenshots',
    videosFolder: 'cypress/videos',

    // Retries
    retries: {
      runMode: 2,
      openMode: 0,
    },

    // Experimental features
    experimentalRunAllSpecs: true,

    setupNodeEvents(on, config) {
      // Node event listeners
      on('task', {
        log(message) {
          console.log(message);
          return null;
        },
      });

      return config;
    },
  },

  env: {
    // Test credentials — override via CYPRESS_TEST_USERNAME / CYPRESS_TEST_PASSWORD
    TEST_USERNAME: process.env.CYPRESS_TEST_USERNAME || 'testuser',
    TEST_PASSWORD: process.env.CYPRESS_TEST_PASSWORD || 'testpass',

    // Cookie name used by auth.py
    COOKIE_NAME: '__Host-ttyd_session',

    // Nginx proxy port (for direct localhost testing)
    NGINX_PORT: 7680,
    AUTH_PORT: 7682,
  },
});
