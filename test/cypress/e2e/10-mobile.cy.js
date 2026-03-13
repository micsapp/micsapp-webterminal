/// <reference types="cypress" />

/**
 * 10 — Mobile / Responsive Layout
 *
 * Covers: MOB-01 through MOB-05
 * - Responsive navbar (hamburger menu)
 * - Special keys visible on mobile
 * - Split buttons hidden on mobile
 * - Touch-friendly elements
 */

describe('Mobile / Responsive Layout', () => {

  // ── Mobile Viewport ───────────────────────────────

  describe('iPhone-size Viewport (375x667)', () => {

    beforeEach(() => {
      cy.viewport(375, 667);
      cy.visitApp();
      cy.get('.navbar', { timeout: 15000 }).should('be.visible');
    });

    it('should show hamburger / dropdown toggle (MOB-01)', () => {
      cy.get('#navDropdown').should('be.visible');
    });

    it('should hide desktop-only nav items (MOB-02)', () => {
      cy.get('.nav-hide-mobile').should('not.be.visible');
    });

    it('should show special keys bar (MOB-03)', () => {
      cy.get('#specialKeys').should('be.visible');
    });

    it('should display the tab bar (MOB-04)', () => {
      cy.get('#tabBar').should('be.visible');
    });

    it('should open dropdown when hamburger is clicked', () => {
      cy.get('#navDropdown').click();
      // Some dropdown should appear
      cy.get('.dropdown-content, .nav-dropdown-content, .dropdown-menu')
        .should('be.visible');
    });

    it('should render the terminal container full width', () => {
      cy.get('#termContainer').then(($el) => {
        const width = $el[0].getBoundingClientRect().width;
        expect(width).to.be.gte(350);
      });
    });
  });

  // ── Tablet Viewport ───────────────────────────────

  describe('Tablet Viewport (768x1024)', () => {

    beforeEach(() => {
      cy.viewport(768, 1024);
      cy.visitApp();
      cy.get('.navbar', { timeout: 15000 }).should('be.visible');
    });

    it('should show navbar elements appropriate for tablet', () => {
      cy.get('.navbar').should('be.visible');
      cy.get('#tabBar').should('be.visible');
    });

    it('should display the terminal container', () => {
      cy.get('#termContainer').should('be.visible');
    });
  });

  // ── Desktop Viewport (control) ────────────────────

  describe('Desktop Viewport (1280x800)', () => {

    beforeEach(() => {
      cy.viewport(1280, 800);
      cy.visitApp();
      cy.get('.navbar', { timeout: 15000 }).should('be.visible');
    });

    it('should show split buttons on desktop', () => {
      cy.get('#splitRightBtn').should('be.visible');
      cy.get('#splitDownBtn').should('be.visible');
      cy.get('#unsplitBtn').should('be.visible');
    });

    it('should show settings / theme / files buttons', () => {
      cy.get('#settingsBtn').should('be.visible');
      cy.get('#themeBtn').should('be.visible');
      cy.get('#filesBtn').should('be.visible');
    });

    it('should hide hamburger on desktop (MOB-05)', () => {
      cy.get('#navDropdown').should('not.be.visible');
    });
  });

  // ── Orientation Change ────────────────────────────

  describe('Landscape vs Portrait', () => {

    it('should adapt to landscape', () => {
      cy.viewport(667, 375); // landscape phone
      cy.visitApp();
      cy.get('#termContainer', { timeout: 15000 }).should('be.visible');
    });

    it('should adapt to portrait', () => {
      cy.viewport(375, 667); // portrait phone
      cy.visitApp();
      cy.get('#termContainer', { timeout: 15000 }).should('be.visible');
    });
  });
});
