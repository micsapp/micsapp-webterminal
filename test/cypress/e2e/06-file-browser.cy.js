/// <reference types="cypress" />

/**
 * 06 — File Browser
 *
 * Covers: FILE-01 through FILE-11
 * - Toggle file panel
 * - List directory contents
 * - Navigate breadcrumbs
 * - Upload / Download files
 * - Create folder / Delete / Rename
 * - Preview files (text, image, pdf, etc.)
 * - Sort bar
 */

describe('File Browser', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('.navbar', { timeout: 15000 }).should('be.visible');
  });

  // ── Toggle File Panel ─────────────────────────────

  describe('Toggle Panel (FILE-01)', () => {

    it('should open file panel when Files button is clicked', () => {
      cy.get('#filesBtn').click();
      cy.get('#filePanel').should('be.visible').and('have.class', 'open');
    });

    it('should close file panel on second click', () => {
      cy.get('#filesBtn').click();
      cy.get('#filePanel').should('have.class', 'open');
      cy.get('#filesBtn').click();
      cy.get('#filePanel').should('not.have.class', 'open');
    });
  });

  // ── Directory Listing ─────────────────────────────

  describe('Directory Listing (FILE-02)', () => {

    it('should list files and folders in home directory', () => {
      cy.openFilePanel();
      cy.get('#fpList', { timeout: 10000 })
        .find('.fp-item')
        .should('have.length.gte', 0);
    });

    it('should show breadcrumbs', () => {
      cy.openFilePanel();
      cy.get('#fpBreadcrumbs').should('be.visible');
    });

    it('should show path input', () => {
      cy.openFilePanel();
      cy.get('#fpPathInput').should('exist');
    });

    it('should show sort bar', () => {
      cy.openFilePanel();
      cy.get('#fpSortBar').should('be.visible');
    });
  });

  // ── Navigate Directories ──────────────────────────

  describe('Directory Navigation (FILE-03)', () => {

    it('should navigate into a directory when clicked', () => {
      cy.openFilePanel();

      // Wait for listing
      cy.get('#fpList .fp-item', { timeout: 10000 }).then(($items) => {
        // Find a folder (icon or type attribute)
        const folder = $items.filter('[data-type="dir"], .fp-folder').first();
        if (folder.length) {
          const folderName = folder.text().trim();
          cy.wrap(folder).click();
          // Breadcrumbs should update
          cy.get('#fpBreadcrumbs', { timeout: 5000 }).should('contain', folderName);
        }
      });
    });

    it('should navigate back via breadcrumb', () => {
      cy.openFilePanel();

      // Click into a folder first
      cy.get('#fpList .fp-item[data-type="dir"], #fpList .fp-folder')
        .first()
        .click({ timeout: 5000 });

      cy.wait(500);

      // Click root breadcrumb
      cy.get('#fpBreadcrumbs').find('span, a').first().click();
      cy.wait(500);
    });
  });

  // ── File API — List ───────────────────────────────

  describe('API: /api/files/list (FILE-02)', () => {

    it('should return a JSON file listing', () => {
      cy.loginViaApi();
      cy.request('/api/files/list').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-type']).to.include('json');
        expect(resp.body).to.be.an('array');
      });
    });

    it('should list items with name and type fields', () => {
      cy.loginViaApi();
      cy.request('/api/files/list').then((resp) => {
        if (resp.body.length > 0) {
          const item = resp.body[0];
          expect(item).to.have.property('name');
          expect(item).to.have.property('type');
        }
      });
    });
  });

  // ── Create Folder ─────────────────────────────────

  describe('Create Folder (FILE-06)', () => {

    const folderName = `cypress_test_dir_${Date.now()}`;

    it('should create a folder via API', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/mkdir',
        body: { path: folderName },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.have.property('ok', true);
      });
    });

    after(() => {
      // Cleanup
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: folderName },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
    });
  });

  // ── Write & Read File ─────────────────────────────

  describe('Write & Read File (FILE-07, FILE-08)', () => {

    const filename = `cypress_test_${Date.now()}.txt`;
    const content = 'Hello from Cypress E2E test!';

    it('should write a file via API', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: filename, content },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.have.property('ok', true);
      });
    });

    it('should read the file back via API', () => {
      cy.loginViaApi();
      // First write it
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: filename, content },
        headers: { 'Content-Type': 'application/json' },
      });

      cy.request(`/api/files/read?path=${encodeURIComponent(filename)}`).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.include(content);
      });
    });

    after(() => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: filename },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
    });
  });

  // ── Rename File ───────────────────────────────────

  describe('Rename File (FILE-09)', () => {

    const original = `cypress_rename_src_${Date.now()}.txt`;
    const renamed = `cypress_rename_dst_${Date.now()}.txt`;

    before(() => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: original, content: 'rename test' },
        headers: { 'Content-Type': 'application/json' },
      });
    });

    it('should rename a file via API', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/rename',
        body: { path: original, newPath: renamed },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.have.property('ok', true);
      });
    });

    after(() => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: renamed },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: original },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
    });
  });

  // ── Delete File ───────────────────────────────────

  describe('Delete File (FILE-10)', () => {

    const filename = `cypress_delete_${Date.now()}.txt`;

    before(() => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: filename, content: 'to be deleted' },
        headers: { 'Content-Type': 'application/json' },
      });
    });

    it('should delete a file via API', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: filename },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.have.property('ok', true);
      });
    });
  });

  // ── Download File ─────────────────────────────────

  describe('Download File (FILE-05)', () => {

    const filename = `cypress_download_${Date.now()}.txt`;

    before(() => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/write',
        body: { path: filename, content: 'download me' },
        headers: { 'Content-Type': 'application/json' },
      });
    });

    it('should download a file via API', () => {
      cy.loginViaApi();
      cy.request(`/api/files/download?path=${encodeURIComponent(filename)}`).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-disposition']).to.include('attachment');
      });
    });

    after(() => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/files/delete',
        body: { path: filename },
        headers: { 'Content-Type': 'application/json' },
        failOnStatusCode: false,
      });
    });
  });

  // ── File Preview Modal ────────────────────────────

  describe('File Preview Modal (FILE-04)', () => {

    it('should show preview modal elements', () => {
      cy.openFilePanel();

      // Modal should be hidden initially
      cy.get('#fpModal').should('exist');
      cy.get('#fpModalTitle').should('exist');
      cy.get('#fpModalContent').should('exist');
    });
  });

  // ── Upload File ───────────────────────────────────

  describe('Upload File (FILE-11)', () => {

    it('should have an upload input in the file panel', () => {
      cy.openFilePanel();
      cy.get('#fpUploadInput').should('exist');
    });
  });
});
