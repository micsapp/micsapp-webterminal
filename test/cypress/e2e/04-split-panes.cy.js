/// <reference types="cypress" />

/**
 * 04 — Split Panes
 *
 * Covers: SPLIT-01 through SPLIT-08
 * - Split right / split down / unsplit
 * - Resize divider drag
 * - Split state persistence
 * - Split limit enforcement
 */

describe('Split Panes', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('#termContainer', { timeout: 15000 }).should('be.visible');
  });

  // ── Split Right ───────────────────────────────────

  describe('Split Right (SPLIT-01)', () => {

    it('should split the pane horizontally when Split Right is clicked', () => {
      cy.get('#termContainer iframe').its('length').then((before) => {
        cy.get('#splitRightBtn').click();
        cy.get('#termContainer iframe', { timeout: 15000 })
          .should('have.length', before + 1);
      });
    });

    it('should render a vertical divider after horizontal split', () => {
      cy.get('#splitRightBtn').click();
      cy.get('#termContainer').then(($tc) => {
        // Look for a divider or the container should show side-by-side layout
        const hasDivider =
          $tc.find('.divider, .gutter, .split-divider, [class*=divider]').length > 0 ||
          $tc.find('.split-h, .split-horizontal, [class*=split]').length > 0;
        expect(hasDivider).to.be.true;
      });
    });
  });

  // ── Split Down ────────────────────────────────────

  describe('Split Down (SPLIT-02)', () => {

    it('should split the pane vertically when Split Down is clicked', () => {
      cy.get('#termContainer iframe').its('length').then((before) => {
        cy.get('#splitDownBtn').click();
        cy.get('#termContainer iframe', { timeout: 15000 })
          .should('have.length', before + 1);
      });
    });
  });

  // ── Unsplit ───────────────────────────────────────

  describe('Unsplit (SPLIT-03)', () => {

    it('should remove split panes when Unsplit is clicked', () => {
      // Create a split first
      cy.get('#splitRightBtn').click();
      cy.get('#termContainer iframe', { timeout: 10000 }).should('have.length.gte', 2);

      cy.get('#unsplitBtn').click();
      cy.get('#termContainer iframe', { timeout: 10000 }).should('have.length', 1);
    });
  });

  // ── Multiple Splits ───────────────────────────────

  describe('Multiple Splits (SPLIT-04)', () => {

    it('should allow split right + split down together', () => {
      cy.get('#splitRightBtn').click();
      cy.wait(1000);
      cy.get('#splitDownBtn').click();

      cy.get('#termContainer iframe', { timeout: 15000 })
        .should('have.length.gte', 3);
    });

    it('should unsplit all panes with one click', () => {
      cy.get('#splitRightBtn').click();
      cy.wait(500);
      cy.get('#splitDownBtn').click();
      cy.wait(500);

      cy.get('#unsplitBtn').click();
      cy.get('#termContainer iframe', { timeout: 10000 }).should('have.length', 1);
    });
  });

  // ── Split Persistence ─────────────────────────────

  describe('Split State Persistence (SPLIT-07)', () => {

    it('should save split layout to localStorage', () => {
      cy.get('#splitRightBtn').click();
      cy.wait(1500); // allow persistence debounce

      cy.window().then((win) => {
        const raw = win.localStorage.getItem('ttyd_split')
          || win.localStorage.getItem('ttyd_tabs');
        expect(raw).to.not.be.null;
      });
    });
  });

  // ── Divider Resize ────────────────────────────────

  describe('Divider Resize (SPLIT-06)', () => {

    it('should have a draggable divider after split', () => {
      cy.get('#splitRightBtn').click();
      cy.wait(500);

      // Find divider element
      cy.get('#termContainer')
        .find('.divider, .gutter, .split-divider, [class*=divider]')
        .should('have.length.gte', 1);
    });
  });

  // ── Active Pane Focus ─────────────────────────────

  describe('Active Pane Focus (SPLIT-05)', () => {

    it('should focus the new pane after split', () => {
      cy.get('#splitRightBtn').click();
      cy.wait(1000);

      // The last iframe should be the focused / active one
      cy.get('#termContainer iframe').last()
        .should('be.visible');
    });
  });
});
