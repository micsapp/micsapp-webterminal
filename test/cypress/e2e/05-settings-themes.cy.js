/// <reference types="cypress" />

/**
 * 05 — Settings & Themes
 *
 * Covers: SET-01 through SET-04, THEME-01 through THEME-03
 * - Settings panel toggle
 * - Font size / family / cursor style / cursor blink / scrollback / leave alert
 * - Apply settings
 * - Theme panel toggle
 * - Theme chip selection
 * - Custom color pickers
 * - Persistence to localStorage
 */

describe('Settings & Themes', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('.navbar', { timeout: 15000 }).should('be.visible');
  });

  // ── Settings Panel ────────────────────────────────

  describe('Settings Panel (SET-01)', () => {

    it('should open settings panel when settings button is clicked', () => {
      cy.get('#settingsBtn').click();
      cy.get('#settingsPanel').should('be.visible');
    });

    it('should close settings panel on second click', () => {
      cy.get('#settingsBtn').click();
      cy.get('#settingsPanel').should('be.visible');
      cy.get('#settingsBtn').click();
      cy.get('#settingsPanel').should('not.be.visible');
    });

    it('should contain font size input', () => {
      cy.openSettings();
      cy.get('#fontSize').should('be.visible');
      cy.get('#fontSize').invoke('val').then((val) => {
        expect(parseInt(val)).to.be.gte(8).and.lte(40);
      });
    });

    it('should contain font family select', () => {
      cy.openSettings();
      cy.get('#fontFamily').should('be.visible');
    });

    it('should contain cursor style select', () => {
      cy.openSettings();
      cy.get('#cursorStyle').should('be.visible');
    });

    it('should contain cursor blink checkbox', () => {
      cy.openSettings();
      cy.get('#cursorBlink').should('exist');
    });

    it('should contain scrollback input', () => {
      cy.openSettings();
      cy.get('#scrollback').should('be.visible');
    });

    it('should contain disable leave alert checkbox', () => {
      cy.openSettings();
      cy.get('#disableLeaveAlert').should('exist');
    });
  });

  // ── Apply Settings ────────────────────────────────

  describe('Apply Settings (SET-02)', () => {

    it('should change font size and persist to localStorage', () => {
      cy.openSettings();

      // Change font size
      cy.get('#fontSize').clear().type('18');

      // Click apply — the button might be a general "Apply" button in the panel
      cy.get('#settingsPanel').find('button, .apply-btn').contains(/apply/i).click();

      cy.wait(500);

      cy.window().then((win) => {
        const settings = JSON.parse(win.localStorage.getItem('ttyd_settings') || '{}');
        expect(settings.fontSize).to.eq(18);
      });
    });

    it('should change cursor style', () => {
      cy.openSettings();
      cy.get('#cursorStyle').select('underline');
      cy.get('#settingsPanel').find('button, .apply-btn').contains(/apply/i).click();

      cy.wait(500);
      cy.window().then((win) => {
        const settings = JSON.parse(win.localStorage.getItem('ttyd_settings') || '{}');
        expect(settings.cursorStyle).to.eq('underline');
      });
    });
  });

  // ── Theme Panel ───────────────────────────────────

  describe('Theme Panel (THEME-01)', () => {

    it('should open theme panel when theme button is clicked', () => {
      cy.get('#themeBtn').click();
      cy.get('#themePanel').should('be.visible');
    });

    it('should close theme panel on second click', () => {
      cy.get('#themeBtn').click();
      cy.get('#themePanel').should('be.visible');
      cy.get('#themeBtn').click();
      cy.get('#themePanel').should('not.be.visible');
    });

    it('should contain theme chips', () => {
      cy.openThemes();
      cy.get('#themePanel .theme-chip').should('have.length.gte', 1);
    });
  });

  // ── Theme Selection ───────────────────────────────

  describe('Theme Selection (THEME-02)', () => {

    it('should apply a theme when a chip is clicked', () => {
      cy.openThemes();

      // Click the second theme chip (different from current)
      cy.get('#themePanel .theme-chip').eq(1).click();

      // The chip should become active/selected
      cy.get('#themePanel .theme-chip.active, #themePanel .theme-chip.selected')
        .should('have.length.gte', 1);
    });

    it('should persist selected theme to localStorage', () => {
      cy.openThemes();
      cy.get('#themePanel .theme-chip').eq(2).click();

      cy.wait(500);
      cy.window().then((win) => {
        const theme = win.localStorage.getItem('ttyd_theme');
        expect(theme).to.not.be.null;
      });
    });
  });

  // ── Custom Color Pickers ──────────────────────────

  describe('Custom Theme Colors (THEME-03)', () => {

    it('should show custom color inputs', () => {
      cy.openThemes();
      cy.get('#colorBg').should('exist');
      cy.get('#colorFg').should('exist');
      cy.get('#colorCursor').should('exist');
      cy.get('#colorSelection').should('exist');
    });

    it('should accept valid hex values', () => {
      cy.openThemes();
      cy.get('#colorBg').invoke('val', '#1a1b26').trigger('input');
      cy.get('#colorBg').should('have.value', '#1a1b26');
    });
  });

  // ── Settings Persistence on Reload ────────────────

  describe('Settings Persistence Across Reload (SET-03)', () => {

    it('should retain settings after page reload', () => {
      cy.openSettings();
      cy.get('#fontSize').clear().type('20');
      cy.get('#settingsPanel').find('button, .apply-btn').contains(/apply/i).click();

      // Reload
      cy.reload();
      cy.get('.navbar', { timeout: 15000 }).should('be.visible');

      cy.window().then((win) => {
        const settings = JSON.parse(win.localStorage.getItem('ttyd_settings') || '{}');
        expect(settings.fontSize).to.eq(20);
      });
    });
  });
});
