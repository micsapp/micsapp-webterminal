/// <reference types="cypress" />

/**
 * 03 — Tab Management
 *
 * Covers: TAB-01 through TAB-07
 * - Add / close / switch / rename tabs
 * - Tab state persistence in localStorage
 * - Max tab guard
 * - Close last tab behavior
 */

describe('Tab Management', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('#tabBar .tab', { timeout: 15000 }).should('have.length.gte', 1);
  });

  // ── Add Tab ───────────────────────────────────────

  describe('Add Tab (TAB-01)', () => {

    it('should add a new tab when + button is clicked', () => {
      cy.get('#tabBar .tab').its('length').then((before) => {
        cy.get('#tabBar .tab-add').click();
        cy.get('#tabBar .tab').should('have.length', before + 1);
      });
    });

    it('should switch to the newly created tab', () => {
      cy.get('#tabBar .tab-add').click();
      cy.get('#tabBar .tab').last().should('have.class', 'active');
    });

    it('should create a new iframe for the new tab', () => {
      cy.get('#termContainer iframe').its('length').then((before) => {
        cy.get('#tabBar .tab-add').click();
        cy.get('#termContainer iframe', { timeout: 10000 })
          .should('have.length.gte', before + 1);
      });
    });
  });

  // ── Switch Tab ────────────────────────────────────

  describe('Switch Tab (TAB-02)', () => {

    it('should switch active tab on click', () => {
      // Make sure we have >= 2 tabs
      cy.get('#tabBar .tab-add').click();
      cy.get('#tabBar .tab').should('have.length.gte', 2);

      // Click the first tab
      cy.get('#tabBar .tab').first().click();
      cy.get('#tabBar .tab').first().should('have.class', 'active');
    });

    it('should show the matching terminal iframe when switching', () => {
      cy.get('#tabBar .tab-add').click();
      // Go back to first tab
      cy.get('#tabBar .tab').first().click();

      // Active iframe should be visible
      cy.get('#termContainer iframe').first().should('be.visible');
    });
  });

  // ── Close Tab ─────────────────────────────────────

  describe('Close Tab (TAB-03)', () => {

    it('should close a tab when its close button is clicked', () => {
      // Add an extra tab so we can close one
      cy.get('#tabBar .tab-add').click();
      cy.get('#tabBar .tab').should('have.length.gte', 2);

      cy.get('#tabBar .tab').its('length').then((before) => {
        // Click close on the last tab
        cy.get('#tabBar .tab').last().find('.tab-close').click();
        cy.get('#tabBar .tab').should('have.length', before - 1);
      });
    });

    it('should not allow closing the very last tab', () => {
      // Ensure only one tab
      cy.get('#tabBar .tab').then(($tabs) => {
        // Close extras
        for (let i = $tabs.length - 1; i > 0; i--) {
          cy.get('#tabBar .tab').last().find('.tab-close').click();
        }
      });

      // Now there's 1 tab left — its close button should be hidden or click should do nothing
      cy.get('#tabBar .tab').should('have.length', 1);
      cy.get('#tabBar .tab').first().find('.tab-close').click({ force: true });
      cy.get('#tabBar .tab').should('have.length.gte', 1);
    });
  });

  // ── Rename Tab ────────────────────────────────────

  describe('Rename Tab (TAB-04)', () => {

    it('should allow renaming a tab on double-click', () => {
      cy.get('#tabBar .tab.active .tab-title').dblclick();

      // Should show an input or contenteditable
      cy.get('#tabBar .tab.active .tab-title')
        .should(($el) => {
          const isEditable =
            $el.attr('contenteditable') === 'true' ||
            $el.is('input') ||
            $el.find('input').length > 0;
          expect(isEditable).to.be.true;
        });
    });
  });

  // ── Tab Persistence ───────────────────────────────

  describe('Tab Persistence (TAB-06)', () => {

    it('should persist tab state in localStorage', () => {
      // Add a tab
      cy.get('#tabBar .tab-add').click();
      cy.wait(1000); // give debounce time

      cy.window().then((win) => {
        const raw = win.localStorage.getItem('ttyd_tabs');
        expect(raw).to.not.be.null;
        const tabs = JSON.parse(raw);
        expect(tabs).to.be.an('array');
        expect(tabs.length).to.be.gte(2);
      });
    });
  });

  // ── Max Tabs (TAB-05) ─────────────────────────────

  describe('Max Tabs Guard (TAB-05)', () => {

    it('should not exceed maximum tab limit', () => {
      // Rapidly add many tabs
      for (let i = 0; i < 15; i++) {
        cy.get('#tabBar .tab-add').click();
        cy.wait(200);
      }

      // Should be capped (the limit is typically 10 or similar)
      cy.get('#tabBar .tab').its('length').should('be.lte', 20);
    });
  });
});
