/// <reference types="cypress" />

/**
 * 02 — SPA Loading & Layout
 *
 * Covers: TERM-01, TERM-02, TERM-04
 * - Main app page served correctly
 * - Navbar elements present
 * - Tab bar rendered
 * - Terminal container / iframe loaded
 * - ttyd port injected
 */

describe('SPA Loading & Layout', () => {

  beforeEach(() => {
    cy.visitApp();
  });

  // ── Navbar ────────────────────────────────────────

  describe('Navbar Elements', () => {

    it('should render the navbar', () => {
      cy.get('.navbar').should('be.visible');
    });

    it('should show the app title', () => {
      cy.get('.nav-title').should('be.visible').and('contain.text', 'Terminal');
    });

    it('should show navigation buttons', () => {
      // Split buttons
      cy.get('#splitRightBtn').should('exist');
      cy.get('#splitDownBtn').should('exist');
      cy.get('#unsplitBtn').should('exist');

      // Quick commands
      cy.get('#cmdsBtn').should('exist');

      // File browser
      cy.get('#filesBtn').should('exist');

      // Settings / Theme buttons
      cy.get('#settingsBtn').should('exist');
      cy.get('#themeBtn').should('exist');
    });

    it('should show the logout button', () => {
      cy.get('.navbar').contains('Logout').should('be.visible');
    });
  });

  // ── Tab Bar ───────────────────────────────────────

  describe('Tab Bar', () => {

    it('should have a tab bar', () => {
      cy.get('#tabBar').should('be.visible');
    });

    it('should have at least one tab on initial load', () => {
      cy.get('#tabBar .tab').should('have.length.gte', 1);
    });

    it('should have one active tab', () => {
      cy.get('#tabBar .tab.active').should('have.length', 1);
    });

    it('should show the add-tab button', () => {
      cy.get('#tabBar .tab-add').should('be.visible');
    });
  });

  // ── Terminal Container ────────────────────────────

  describe('Terminal Container', () => {

    it('should render the terminal container', () => {
      cy.get('#termContainer').should('be.visible');
    });

    it('should load a ttyd iframe inside the terminal container', () => {
      cy.get('#termContainer iframe', { timeout: 20000 })
        .should('have.length.gte', 1)
        .first()
        .should('have.attr', 'src');
    });

    it('should inject the correct ttyd port into the iframe src', () => {
      cy.get('#termContainer iframe', { timeout: 20000 })
        .first()
        .invoke('attr', 'src')
        .then((src) => {
          // Should contain the ttyd base path (e.g. /ttyd7700/)
          expect(src).to.match(/\/ttyd\d+\//);
        });
    });
  });

  // ── term-hook.js ──────────────────────────────────

  describe('Term Hook Script', () => {

    it('should serve term-hook.js', () => {
      cy.loginViaApi();
      cy.request('/api/term-hook.js').then((resp) => {
        expect(resp.status).to.eq(200);
        expect(resp.headers['content-type']).to.include('javascript');
        expect(resp.body).to.include('__TTYD_PORT__');
      });
    });
  });

  // ── Page Title & Viewport ─────────────────────────

  describe('Page Metadata', () => {

    it('should have a meaningful page title', () => {
      cy.title().should('not.be.empty');
    });

    it('should include viewport meta for responsive design', () => {
      cy.document().then((doc) => {
        const meta = doc.querySelector('meta[name="viewport"]');
        expect(meta).to.not.be.null;
        expect(meta.getAttribute('content')).to.include('width=device-width');
      });
    });
  });

  // ── Special Keys Bar ──────────────────────────────

  describe('Special Keys', () => {

    it('should have a special keys section', () => {
      cy.get('#specialKeys').should('exist');
    });
  });
});
