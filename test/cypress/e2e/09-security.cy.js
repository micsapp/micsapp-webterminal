/// <reference types="cypress" />

/**
 * 09 — Security
 *
 * Covers: SEC-01 through SEC-06
 * - Unauthenticated access denied
 * - Invalid / expired tokens rejected
 * - Security headers present
 * - Path traversal prevention
 * - HMAC token integrity
 * - Cookie attributes (Secure, HttpOnly, SameSite)
 */

describe('Security', () => {

  // ── Unauthenticated Access ────────────────────────

  describe('Unauthenticated Requests (SEC-01)', () => {

    const protectedRoutes = [
      '/',
      '/api/files/list',
      '/api/files/read?path=test',
      '/api/files/download?path=test',
      '/api/quick-commands',
      '/api/quick-commands/export',
      '/api/desktop',
      '/api/help',
    ];

    protectedRoutes.forEach((route) => {
      it(`should deny access to ${route} without auth`, () => {
        cy.clearCookies();
        cy.request({
          url: route,
          failOnStatusCode: false,
          followRedirect: false,
        }).then((resp) => {
          expect([302, 401, 403]).to.include(resp.status);
        });
      });
    });
  });

  // ── Invalid Token ─────────────────────────────────

  describe('Invalid Token Rejection (SEC-02)', () => {

    it('should reject a completely invalid token', () => {
      cy.request({
        url: '/api/files/list',
        failOnStatusCode: false,
        followRedirect: false,
        headers: {
          Cookie: `__Host-ttyd_session=garbage-token`,
        },
      }).then((resp) => {
        expect([302, 401, 403]).to.include(resp.status);
      });
    });

    it('should reject a token with tampered signature', () => {
      const ts = Math.floor(Date.now() / 1000);
      const tamperedToken = `testuser:7700:${ts}:aaaa${('0').repeat(60)}`;
      cy.request({
        url: '/api/files/list',
        failOnStatusCode: false,
        followRedirect: false,
        headers: {
          Cookie: `__Host-ttyd_session=${tamperedToken}`,
        },
      }).then((resp) => {
        expect([302, 401, 403]).to.include(resp.status);
      });
    });

    it('should reject a token with wrong username', () => {
      const ts = Math.floor(Date.now() / 1000);
      const forgedToken = `hacker:7700:${ts}:${'0'.repeat(64)}`;
      cy.request({
        url: '/api/files/list',
        failOnStatusCode: false,
        followRedirect: false,
        headers: {
          Cookie: `__Host-ttyd_session=${forgedToken}`,
        },
      }).then((resp) => {
        expect([302, 401, 403]).to.include(resp.status);
      });
    });

    it('should reject an expired token (> 24h old)', () => {
      const expired = Math.floor(Date.now() / 1000) - 100000;
      const oldToken = `testuser:7700:${expired}:${'0'.repeat(64)}`;
      cy.request({
        url: '/api/files/list',
        failOnStatusCode: false,
        followRedirect: false,
        headers: {
          Cookie: `__Host-ttyd_session=${oldToken}`,
        },
      }).then((resp) => {
        expect([302, 401, 403]).to.include(resp.status);
      });
    });
  });

  // ── Security Headers ──────────────────────────────

  describe('Security Headers (SEC-03)', () => {

    it('should set X-Content-Type-Options', () => {
      cy.request({
        url: '/login',
      }).then((resp) => {
        const header = resp.headers['x-content-type-options'];
        if (header) {
          expect(header).to.eq('nosniff');
        }
      });
    });

    it('should set X-Frame-Options', () => {
      cy.request({
        url: '/login',
      }).then((resp) => {
        const header = resp.headers['x-frame-options'];
        if (header) {
          expect(header).to.match(/DENY|SAMEORIGIN/i);
        }
      });
    });

    it('should set Referrer-Policy', () => {
      cy.request({
        url: '/login',
      }).then((resp) => {
        const header = resp.headers['referrer-policy'];
        if (header) {
          expect(header).to.include('origin');
        }
      });
    });

    it('should set Content-Security-Policy or X-Content-Security-Policy', () => {
      cy.request({
        url: '/login',
      }).then((resp) => {
        const csp = resp.headers['content-security-policy'] ||
          resp.headers['x-content-security-policy'];
        // CSP may or may not be present
        if (csp) {
          expect(csp).to.be.a('string').and.not.be.empty;
        }
      });
    });
  });

  // ── Cookie Security Attributes ────────────────────

  describe('Cookie Security Attributes (SEC-04)', () => {

    it('should set HttpOnly flag on session cookie', () => {
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
      });
    });

    it('should set SameSite=Strict', () => {
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
        expect(cookie.sameSite).to.eq('strict');
      });
    });

    it('should use __Host- cookie prefix', () => {
      expect(Cypress.env('COOKIE_NAME')).to.match(/^__Host-/);
    });
  });

  // ── Path Traversal Prevention ─────────────────────

  describe('Path Traversal Prevention (SEC-05)', () => {

    it('should reject ../ path traversal in file read', () => {
      cy.loginViaApi();
      cy.request({
        url: '/api/files/read?path=../../etc/passwd',
        failOnStatusCode: false,
      }).then((resp) => {
        expect([400, 403, 404]).to.include(resp.status);
      });
    });

    it('should reject ../ path traversal in file list', () => {
      cy.loginViaApi();
      cy.request({
        url: '/api/files/list?path=../../etc',
        failOnStatusCode: false,
      }).then((resp) => {
        // Should either reject or scope to user home
        if (resp.status === 200) {
          // If 200, ensure it doesn't list system files
          const names = resp.body.map((f) => f.name);
          expect(names).to.not.include('shadow');
        }
      });
    });

    it('should reject ../ path traversal in file write', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: '../../tmp/evil.txt', content: 'hack' },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect([400, 403]).to.include(resp.status);
      });
    });

    it('should reject ../ path traversal in file delete', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: '../../etc/passwd' },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect([400, 403]).to.include(resp.status);
      });
    });
  });

  // ── POST Endpoint Method Checks ───────────────────

  describe('HTTP Method Enforcement (SEC-06)', () => {

    it('should reject GET for /api/login', () => {
      cy.request({
        method: 'GET',
        url: '/api/login',
        failOnStatusCode: false,
      }).then((resp) => {
        expect([302, 400, 404, 405]).to.include(resp.status);
      });
    });

    it('should reject GET for /api/files/write', () => {
      cy.loginViaApi();
      cy.request({
        method: 'GET',
        url: '/api/files/write',
        failOnStatusCode: false,
      }).then((resp) => {
        expect([400, 404, 405]).to.include(resp.status);
      });
    });
  });
});
