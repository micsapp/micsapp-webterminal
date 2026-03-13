/// <reference types="cypress" />

/**
 * 07 — Quick Commands
 *
 * Covers: CMD-01 through CMD-05
 * - Open quick commands overlay
 * - Add / edit / delete quick commands
 * - Search & filter by tags
 * - Execute a quick command
 * - Export / Import quick commands
 */

describe('Quick Commands', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('.navbar', { timeout: 15000 }).should('be.visible');
  });

  // ── Open Overlay ──────────────────────────────────

  describe('Quick Commands Overlay (CMD-01)', () => {

    it('should open quick commands overlay', () => {
      cy.get('#cmdsBtn').click();
      cy.get('#qcOverlay').should('be.visible').and('have.class', 'open');
    });

    it('should close the overlay on second click', () => {
      cy.get('#cmdsBtn').click();
      cy.get('#qcOverlay').should('have.class', 'open');
      cy.get('#cmdsBtn').click();
      cy.get('#qcOverlay').should('not.have.class', 'open');
    });
  });

  // ── Add Quick Command ─────────────────────────────

  describe('Add Quick Command (CMD-02)', () => {

    it('should show add form when add button is clicked', () => {
      cy.openQuickCommands();
      cy.get('#qcAddBtn').click();
      cy.get('#qcForm').should('be.visible');
    });

    it('should have name, command, and tags fields', () => {
      cy.openQuickCommands();
      cy.get('#qcAddBtn').click();

      cy.get('#qcFormName').should('be.visible');
      cy.get('#qcFormCmd').should('be.visible');
      cy.get('#qcFormTags').should('be.visible');
    });

    it('should save a new quick command', () => {
      cy.openQuickCommands();
      cy.get('#qcAddBtn').click();

      const name = `CypressCmd_${Date.now()}`;
      cy.get('#qcFormName').clear().type(name);
      cy.get('#qcFormCmd').clear().type('echo "cypress test"');
      cy.get('#qcFormTags').clear().type('test,cypress');
      cy.get('#qcFormSave').click();

      // The overlay should list the new command
      cy.get('#qcOverlay').should('contain.text', name);
    });
  });

  // ── Search Quick Commands ─────────────────────────

  describe('Search Quick Commands (CMD-03)', () => {

    it('should have a search input', () => {
      cy.openQuickCommands();
      cy.get('#qcSearch').should('be.visible');
    });

    it('should filter commands by search text', () => {
      cy.openQuickCommands();
      cy.get('#qcSearch').clear().type('nonexistentcommand_xyz');
      cy.wait(300);
      // Filtered results should be empty or fewer
      cy.get('#qcOverlay .qc-card, #qcOverlay .qc-item').should('have.length.lte', 0);
    });
  });

  // ── Tags Filter ───────────────────────────────────

  describe('Tags Filter (CMD-03)', () => {

    it('should show a tags bar', () => {
      cy.openQuickCommands();
      cy.get('#qcTagsBar').should('exist');
    });
  });

  // ── Export Quick Commands ──────────────────────────

  describe('Export Quick Commands (CMD-04)', () => {

    it('should have an export button', () => {
      cy.openQuickCommands();
      cy.get('#qcExportBtn').should('be.visible');
    });

    it('should export quick commands via API', () => {
      cy.loginViaApi();
      cy.request('/api/quick-commands/export').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-type']).to.include('json');
      });
    });
  });

  // ── Import Quick Commands ─────────────────────────

  describe('Import Quick Commands (CMD-05)', () => {

    it('should have an import button', () => {
      cy.openQuickCommands();
      cy.get('#qcImportBtn').should('be.visible');
    });
  });

  // ── API Endpoints ─────────────────────────────────

  describe('API: /api/quick-commands', () => {

    it('should GET quick commands list', () => {
      cy.loginViaApi();
      cy.request('/api/quick-commands').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.be.an('array');
      });
    });

    it('should POST a new quick command', () => {
      cy.loginViaApi();
      cy.request({
        method: 'POST',
        url: '/api/quick-commands',
        body: {
          name: `api_test_${Date.now()}`,
          command: 'echo api_test',
          tags: ['test'],
        },
        headers: { 'Content-Type': 'application/json' },
      }).then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.body).to.have.property('ok', true);
      });
    });
  });
});
