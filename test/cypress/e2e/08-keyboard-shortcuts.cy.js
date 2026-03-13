/// <reference types="cypress" />

/**
 * 08 — Keyboard Shortcuts
 *
 * Covers: TAB-07, SPLIT-08
 * - Ctrl+Shift+T  → New tab
 * - Ctrl+Shift+W  → Close tab
 * - Ctrl+Shift+]  → Next tab
 * - Ctrl+Shift+[  → Previous tab
 * - Ctrl+Shift+\  → Split right
 * - Ctrl+Shift+-  → Split down
 * - Ctrl+Shift+U  → Unsplit
 * - Ctrl+Shift+E  → Toggle file panel
 * - Escape         → Close modals / panels
 */

describe('Keyboard Shortcuts', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('#tabBar', { timeout: 15000 }).should('be.visible');
  });

  /**
   * Helper: trigger a keyboard shortcut on the body
   */
  const shortcut = (key, opts = {}) => {
    cy.get('body').trigger('keydown', {
      key,
      ctrlKey: true,
      shiftKey: true,
      bubbles: true,
      ...opts,
    });
  };

  // ── New Tab Shortcut ──────────────────────────────

  describe('Ctrl+Shift+T — New Tab', () => {

    it('should create a new tab', () => {
      cy.get('#tabBar .tab').its('length').then((before) => {
        shortcut('T');
        cy.get('#tabBar .tab').should('have.length', before + 1);
      });
    });
  });

  // ── Close Tab Shortcut ────────────────────────────

  describe('Ctrl+Shift+W — Close Tab', () => {

    it('should close the active tab (when > 1 tab)', () => {
      // First, add a second tab
      shortcut('T');
      cy.get('#tabBar .tab').should('have.length.gte', 2);

      cy.get('#tabBar .tab').its('length').then((before) => {
        shortcut('W');
        cy.get('#tabBar .tab').should('have.length', before - 1);
      });
    });
  });

  // ── Next / Previous Tab Shortcuts ─────────────────

  describe('Ctrl+Shift+] / [ — Switch Tabs', () => {

    it('should switch to the next tab', () => {
      // Ensure at least 2 tabs
      shortcut('T');
      cy.get('#tabBar .tab').should('have.length.gte', 2);

      // Go back to first tab
      cy.get('#tabBar .tab').first().click();
      cy.get('#tabBar .tab').first().should('have.class', 'active');

      // Shortcut: next tab
      shortcut(']');
      cy.get('#tabBar .tab.active').then(($el) => {
        // Should not be the first tab
        cy.get('#tabBar .tab').first().then(($first) => {
          expect($el[0]).to.not.eq($first[0]);
        });
      });
    });

    it('should switch to the previous tab', () => {
      shortcut('T');
      cy.get('#tabBar .tab').should('have.length.gte', 2);

      // Click the last tab
      cy.get('#tabBar .tab').last().click();

      // Shortcut: previous tab
      shortcut('[');
      cy.get('#tabBar .tab.active').then(($el) => {
        cy.get('#tabBar .tab').last().then(($last) => {
          expect($el[0]).to.not.eq($last[0]);
        });
      });
    });
  });

  // ── Split Shortcuts ───────────────────────────────

  describe('Ctrl+Shift+\\ — Split Right', () => {

    it('should split right', () => {
      cy.get('#termContainer iframe').its('length').then((before) => {
        shortcut('\\');
        cy.get('#termContainer iframe', { timeout: 10000 })
          .should('have.length', before + 1);
      });
    });
  });

  describe('Ctrl+Shift+- — Split Down', () => {

    it('should split down', () => {
      cy.get('#termContainer iframe').its('length').then((before) => {
        shortcut('-');
        cy.get('#termContainer iframe', { timeout: 10000 })
          .should('have.length', before + 1);
      });
    });
  });

  describe('Ctrl+Shift+U — Unsplit', () => {

    it('should unsplit all panes', () => {
      // Create a split first
      shortcut('\\');
      cy.get('#termContainer iframe', { timeout: 10000 }).should('have.length.gte', 2);

      shortcut('U');
      cy.get('#termContainer iframe', { timeout: 10000 }).should('have.length', 1);
    });
  });

  // ── Toggle File Panel Shortcut ────────────────────

  describe('Ctrl+Shift+E — Toggle File Panel', () => {

    it('should toggle the file panel', () => {
      shortcut('E');
      cy.get('#filePanel').should('have.class', 'open');

      shortcut('E');
      cy.get('#filePanel').should('not.have.class', 'open');
    });
  });

  // ── Escape to Close Modals ────────────────────────

  describe('Escape — Close Modals', () => {

    it('should close quick commands overlay on Escape', () => {
      cy.get('#cmdsBtn').click();
      cy.get('#qcOverlay').should('have.class', 'open');

      cy.get('body').trigger('keydown', { key: 'Escape', bubbles: true });
      cy.get('#qcOverlay').should('not.have.class', 'open');
    });

    it('should close file panel on Escape', () => {
      cy.get('#filesBtn').click();
      cy.get('#filePanel').should('have.class', 'open');

      cy.get('body').trigger('keydown', { key: 'Escape', bubbles: true });
      cy.get('#filePanel').should('not.have.class', 'open');
    });

    it('should close settings panel on Escape', () => {
      cy.get('#settingsBtn').click();
      cy.get('#settingsPanel').should('be.visible');

      cy.get('body').trigger('keydown', { key: 'Escape', bubbles: true });
      cy.get('#settingsPanel').should('not.be.visible');
    });
  });
});
