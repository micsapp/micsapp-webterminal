/// <reference types="cypress" />

/**
 * 11 — API Endpoints (comprehensive)
 *
 * Covers all GET / POST endpoints served by auth.py:
 * - GET  /login, /, /api/term-hook.js, /api/auth, /api/desktop,
 *        /api/help, /api/files/list, /api/files/read, /api/files/download,
 *        /api/quick-commands, /api/quick-commands/export
 * - POST /api/login, /api/files/upload, /api/files/write,
 *        /api/files/mkdir, /api/files/delete, /api/files/rename,
 *        /api/quick-commands, /api/quick-commands/import
 */

describe('API Endpoints', () => {

  // ── Public Endpoints ──────────────────────────────

  describe('Public (no auth required)', () => {

    it('GET /login — returns login page', () => {
      cy.request('/login').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.include('Sign in');
      });
    });

    it('POST /api/login — valid credentials', () => {
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
        expect(resp.body.ok).to.eq(true);
        expect(resp.body.port).to.be.a('number');
      });
    });

    it('POST /api/login — invalid credentials', () => {
      cy.request({
        method: 'POST',
        url: '/api/login',
        body: { username: 'bad', password: 'bad' },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect(resp.status).to.eq(401);
        expect(resp.body.ok).to.eq(false);
      });
    });
  });

  // ── Authenticated GET Endpoints ───────────────────

  describe('Authenticated GET Endpoints', () => {

    beforeEach(() => {
      cy.loginViaApi();
    });

    it('GET / — returns main SPA', () => {
      cy.request('/').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.include('termContainer');
      });
    });

    it('GET /api/term-hook.js — returns JavaScript', () => {
      cy.request('/api/term-hook.js').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-type']).to.include('javascript');
        expect(resp.body).to.include('__TTYD_PORT__');
      });
    });

    it('GET /api/auth — returns 200 for valid session', () => {
      cy.request({ url: '/api/auth', failOnStatusCode: false }).then((resp) => {
        expect(resp.status).to.eq(200);
      });
    });

    it('GET /api/help — returns help content', () => {
      cy.request('/api/help').then((resp) => {
        expect(resp.status).to.eq(200);
      });
    });

    it('GET /api/files/list — returns directory listing', () => {
      cy.request('/api/files/list').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.be.an('array');
      });
    });

    it('GET /api/files/list?path=. — lists current directory', () => {
      cy.request('/api/files/list?path=.').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.be.an('array');
      });
    });

    it('GET /api/quick-commands — returns commands array', () => {
      cy.request('/api/quick-commands').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.be.an('array');
      });
    });

    it('GET /api/quick-commands/export — returns JSON export', () => {
      cy.request('/api/quick-commands/export').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-type']).to.include('json');
      });
    });

    it('GET /api/desktop — returns desktop / VNC page or error', () => {
      cy.request({
        url: '/api/desktop',
        failOnStatusCode: false,
      }).then((resp) => {
        // Desktop might be 200 or 503 depending on server config
        expect([200, 302, 503]).to.include(resp.status);
      });
    });
  });

  // ── Authenticated POST Endpoints — File Ops ───────

  describe('Authenticated POST Endpoints — File Operations', () => {

    const testFile = `api_e2e_${Date.now()}.txt`;
    const testDir = `api_e2e_dir_${Date.now()}`;

    beforeEach(() => {
      cy.loginViaApi();
    });

    it('POST /api/files/write — create a file', () => {
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: testFile, content: 'API test content' },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body.ok).to.eq(true);
      });
    });

    it('GET /api/files/read — read the file', () => {
      // ensure file exists
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: testFile, content: 'read me back' },
        headers: { 'Content-Type': 'application/json' },
      });

      cy.request(`/api/files/read?path=${encodeURIComponent(testFile)}`).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.include('read me back');
      });
    });

    it('GET /api/files/download — download the file', () => {
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: testFile, content: 'download me' },
        headers: { 'Content-Type': 'application/json' },
      });

      cy.request(`/api/files/download?path=${encodeURIComponent(testFile)}`).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-disposition']).to.include('attachment');
      });
    });

    it('POST /api/files/mkdir — create a directory', () => {
      cy.request({
        method: 'POST',
        url: '/api/files/mkdir',
        body: { path: testDir },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body.ok).to.eq(true);
      });
    });

    it('POST /api/files/rename — rename a file', () => {
      const renamedFile = `api_e2e_renamed_${Date.now()}.txt`;
      // Ensure source exists
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: testFile, content: 'rename me' },
        headers: { 'Content-Type': 'application/json' },
      });

      cy.request({
        method: 'POST',
        url: '/api/files/rename',
        body: { path: testFile, newPath: renamedFile },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body.ok).to.eq(true);
      });

      // Cleanup renamed file
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: renamedFile },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
    });

    it('POST /api/files/delete — delete a file', () => {
      // Ensure file exists
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: testFile, content: 'delete me' },
        headers: { 'Content-Type': 'application/json' },
      });

      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: testFile },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body.ok).to.eq(true);
      });
    });

    afterEach(() => {
      // Best-effort cleanup
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: testFile },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: testDir },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
    });
  });

  // ── Authenticated POST — Quick Commands ───────────

  describe('Authenticated POST Endpoints — Quick Commands', () => {

    beforeEach(() => {
      cy.loginViaApi();
    });

    it('POST /api/quick-commands — save a new command', () => {
      cy.request({
        method: 'POST',
        url: '/api/quick-commands',
        body: {
          name: `api_qc_${Date.now()}`,
          command: 'echo api_qc_test',
          tags: ['api', 'test'],
        },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body.ok).to.eq(true);
      });
    });

    it('POST /api/quick-commands/import — import commands', () => {
      cy.request({
        method: 'POST',
        url: '/api/quick-commands/import',
        body: [
          { name: 'import_test', command: 'echo imported', tags: ['import'] },
        ],
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      }).then((resp) => {
        expect([200, 201]).to.include(resp.status);
      });
    });
  });

  // ── 404 for Unknown Routes ────────────────────────

  describe('Unknown Routes', () => {

    it('should return 404 for unknown API path', () => {
      cy.loginViaApi();
      cy.request({
        url: '/api/nonexistent',
        failOnStatusCode: false,
      }).then((resp) => {
        expect([302, 404]).to.include(resp.status);
      });
    });
  });
});
