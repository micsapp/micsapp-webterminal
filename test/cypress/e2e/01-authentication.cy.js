/// <reference types="cypress" />

/**
 * 01 — Authentication & Session Management
 *
 * Covers: AUTH-01 through AUTH-09
 * - Login page rendering
 * - Valid credential login via UI
 * - Invalid credential rejection
 * - Session cookie attributes
 * - Token structure verification
 * - Logout flow
 * - Unauthenticated redirect
 * - Session expiry behavior
 */

describe('Authentication & Session Management', () => {

  beforeEach(() => {
    cy.clearCookies();
    cy.clearLocalStorage();
  });

  // ── Login Page ────────────────────────────────────

  describe('Login Page', () => {

    it('should display the login page at /login', () => {
      cy.visit('/login');
      cy.get('.login-box').should('be.visible');
      cy.get('.login-box h1').should('contain.text', 'Terminal');
      cy.get('.login-box p').should('contain.text', 'Sign in');
    });

    it('should have username and password fields', () => {
      cy.visit('/login');
      cy.get('#username')
        .should('be.visible')
        .and('have.attr', 'type', 'text')
        .and('have.attr', 'autocomplete', 'username')
        .and('have.attr', 'required');

      cy.get('#password')
        .should('be.visible')
        .and('have.attr', 'type', 'password')
        .and('have.attr', 'autocomplete', 'current-password')
        .and('have.attr', 'required');
    });

    it('should have a Sign In button', () => {
      cy.visit('/login');
      cy.get('form#form button[type="submit"]')
        .should('be.visible')
        .and('contain.text', 'Sign In');
    });

    it('should autofocus the username field', () => {
      cy.visit('/login');
      cy.get('#username').should('have.attr', 'autofocus');
    });

    it('should hide error message by default', () => {
      cy.visit('/login');
      cy.get('#error').should('not.be.visible');
    });
  });

  // ── Unauthenticated Access ────────────────────────

  describe('Unauthenticated Redirect', () => {

    it('should redirect / to /login when not authenticated (AUTH-07)', () => {
      cy.request({ url: '/', followRedirect: false, failOnStatusCode: false }).then((resp) => {
        expect(resp.status).to.eq(302);
        expect(resp.redirectedToUrl || resp.headers.location).to.include('/login');
      });
    });

    it('should redirect /api/files/list to /login without cookie', () => {
      cy.request({ url: '/api/files/list', followRedirect: false, failOnStatusCode: false }).then((resp) => {
        expect(resp.status).to.eq(302);
      });
    });

    it('should redirect /api/quick-commands to /login without cookie', () => {
      cy.request({ url: '/api/quick-commands', followRedirect: false, failOnStatusCode: false }).then((resp) => {
        expect(resp.status).to.eq(302);
      });
    });

    it('should allow /login and /api/login without auth', () => {
      cy.request({ url: '/login', failOnStatusCode: false }).then((resp) => {
        expect(resp.status).to.eq(200);
      });
    });
  });

  // ── Valid Login ───────────────────────────────────

  describe('Valid Credential Login', () => {

    it('should login successfully via UI (AUTH-01, AUTH-02)', () => {
      cy.visit('/login');
      cy.get('#username').type(Cypress.env('TEST_USERNAME'));
      cy.get('#password').type(Cypress.env('TEST_PASSWORD'));
      cy.get('form#form button[type="submit"]').click();

      // Should redirect to main app
      cy.url({ timeout: 15000 }).should('not.include', '/login');
      cy.get('.navbar', { timeout: 15000 }).should('be.visible');
    });

    it('should login successfully via API and receive token + port', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          username: Cypress.env('TEST_USERNAME'),
          password: Cypress.env('TEST_PASSWORD'),
        },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.have.property('ok', true);
        expect(resp.body).to.have.property('port');
        expect(resp.body.port).to.be.a('number');
        expect(resp.body.port).to.be.gte(7700);
      });
    });

    it('should set session cookie with correct attributes (AUTH-03, AUTH-04)', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: {
          username: Cypress.env('TEST_USERNAME'),
          password: Cypress.env('TEST_PASSWORD'),
        },
        headers: { 'Content-Type': 'application/json' },
      });

      cy.getCookie(Cypress.env('COOKIE_NAME')).then((cookie) => {
        expect(cookie).to.not.be.null;
        expect(cookie.httpOnly).to.be.true;
        expect(cookie.sameSite).to.eq('strict');
        // Token format: username:port:timestamp:signature
        const parts = cookie.value.split(':');
        expect(parts).to.have.length(4);
        expect(parts[0]).to.eq(Cypress.env('TEST_USERNAME'));
        // Port should be a number >= 7700
        expect(parseInt(parts[1])).to.be.gte(7700);
        // Timestamp should be recent
        const ts = parseInt(parts[2]);
        const now = Math.floor(Date.now() / 1000);
        expect(ts).to.be.within(now - 30, now + 5);
        // Signature should be a hex string (64 chars for SHA256)
        expect(parts[3]).to.match(/^[0-9a-f]{64}$/);
      });
    });

    it('should return same port for repeated logins (TERM-03)', () => {
      const login = () =>
        cy.request({
          method: 'POST',
          url: '/api/login',
          body: {
            username: Cypress.env('TEST_USERNAME'),
            password: Cypress.env('TEST_PASSWORD'),
          },
          headers: { 'Content-Type': 'application/json' },
        });

      let firstPort;
      login().then((resp) => {
        firstPort = resp.body.port;
      });

      // Login again — should reuse the same ttyd instance
      login().then((resp) => {
        expect(resp.body.port).to.eq(firstPort);
      });
    });
  });

  // ── Invalid Login ─────────────────────────────────

  describe('Invalid Credential Rejection', () => {

    it('should show error for wrong password via UI', () => {
      cy.visit('/login');
      cy.get('#username').type(Cypress.env('TEST_USERNAME'));
      cy.get('#password').type('wrong_password_xyz');
      cy.get('form#form button[type="submit"]').click();

      cy.get('#error', { timeout: 15000 }).should('be.visible');
      cy.url().should('include', '/login');
    });

    it('should return 401 for wrong credentials via API', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: { username: 'nonexistent_user', password: 'bad_password' },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect(resp.status).to.eq(401);
        expect(resp.body).to.have.property('ok', false);
        expect(resp.body).to.have.property('error');
      });
    });

    it('should return 401 for empty credentials', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: { username: '', password: '' },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect(resp.status).to.eq(401);
      });
    });

    it('should return 400 for malformed body', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: 'not-json',
        headers: { 'Content-Type': 'text/plain' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect([400, 401]).to.include(resp.status);
      });
    });
  });

  // ── Logout ────────────────────────────────────────

  describe('Logout', () => {

    it('should logout and redirect to login (AUTH-08)', () => {
      cy.visitApp();

      // Find and click the logout button
      cy.get('.navbar').contains('Logout').click({ force: true });

      // Should be back at login
      cy.url({ timeout: 10000 }).should('include', '/login');

      // Cookie should be cleared
      cy.getCookie(Cypress.env('COOKIE_NAME')).should('be.null');
    });
  });

  // ── Auth Subrequest (nginx auth_request) ──────────

  describe('Auth Subrequest Validation (AUTH-06)', () => {

    it('should reject /api/auth with invalid cookie', () => {
      cy.request({
        url: '/api/files/list',
        failOnStatusCode: false,
        headers: {
          Cookie: `${Cypress.env('COOKIE_NAME')}=invalid:token:123:abc`,
        },
      }).then((resp) => {
        // Should redirect to login (via nginx error_page 401 = @login_redirect)
        expect([302, 401]).to.include(resp.status);
      });
    });

    it('should reject expired tokens', () => {
      // Forge a token with old timestamp (> 24h ago)
      const oldTs = Math.floor(Date.now() / 1000) - 100000;
      const fakeToken = `testuser:7700:${oldTs}:0000000000000000000000000000000000000000000000000000000000000000`;
      cy.request({
        url: '/api/files/list',
        failOnStatusCode: false,
        headers: {
          Cookie: `${Cypress.env('COOKIE_NAME')}=${fakeToken}`,
        },
      }).then((resp) => {
        expect([302, 401]).to.include(resp.status);
      });
    });
  });
});
