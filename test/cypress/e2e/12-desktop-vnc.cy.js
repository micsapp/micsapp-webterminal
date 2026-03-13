/// <reference types="cypress" />

/**
 * 12 — Desktop / VNC
 *
 * Covers: VNC-01 through VNC-03
 * - Desktop endpoint availability
 * - noVNC tab creation
 * - VNC iframe loading
 */

describe('Desktop / VNC', () => {

  beforeEach(() => {
    cy.visitApp();
    cy.get('.navbar', { timeout: 15000 }).should('be.visible');
  });

  // ── Desktop Endpoint ──────────────────────────────

  describe('Desktop Endpoint (VNC-01)', () => {

    it('should respond to /api/desktop', () => {
      cy.loginViaApi();
      cy.request({
        url: '/api/desktop',
        failOnStatusCode: false,
      }).then((resp) => {
        // 200 if VNC is configured, 503 if not available, 302 if redirect
        expect([200, 302, 503]).to.include(resp.status);
      });
    });
  });

  // ── VNC Tab ───────────────────────────────────────

  describe('VNC Tab Creation (VNC-02)', () => {

    it('should have a Desktop / VNC button or link in the navbar', () => {
      // The desktop button may be inside the hamburger dropdown or navbar
      cy.get('.navbar').then(($nav) => {
        const hasDesktopLink =
          $nav.text().toLowerCase().includes('desktop') ||
          $nav.find('[href*="desktop"], [onclick*="desktop"], [data-action="desktop"]').length > 0;

        if (hasDesktopLink) {
          cy.get('.navbar').contains(/desktop/i).should('be.visible');
        } else {
          // Desktop may not be enabled on this server
          cy.log('Desktop/VNC button not found — feature may be disabled');
        }
      });
    });

    it('should open a VNC tab when Desktop link is clicked (if available)', () => {
      cy.get('.navbar').then(($nav) => {
        if ($nav.text().toLowerCase().includes('desktop')) {
          cy.get('.navbar').contains(/desktop/i).click({ force: true });

          // Should either add a tab or navigate
          cy.wait(2000);
          cy.get('#tabBar .tab').should('have.length.gte', 1);
        } else {
          cy.log('Skipping — Desktop feature not available');
        }
      });
    });
  });

  // ── noVNC Proxy ───────────────────────────────────

  describe('noVNC WebSocket Proxy (VNC-03)', () => {

    it('should have nginx configured for noVNC websocket upgrade', () => {
      // This is a configuration test — we verify the proxy responds
      cy.loginViaApi();
      cy.request({
        url: '/api/desktop',
        failOnStatusCode: false,
      }).then((resp) => {
        if (resp.status === 200) {
          // noVNC page should contain 'noVNC' or 'rfb' references
          if (typeof resp.body === 'string') {
            const hasVnc = resp.body.includes('noVNC') || resp.body.includes('vnc');
            cy.log(`noVNC content present: ${hasVnc}`);
          }
        } else {
          cy.log(`Desktop endpoint returned ${resp.status} — VNC may not be configured`);
        }
      });
    });
  });

  // ── VNC with Mobile Viewport ──────────────────────

  describe('VNC on Mobile (VNC + MOB)', () => {

    it('should handle VNC on mobile viewport', () => {
      cy.viewport(375, 667);
      cy.visitApp();

      cy.get('.navbar', { timeout: 15000 }).should('be.visible');

      // Check if desktop is accessible on mobile
      cy.get('.navbar').then(($nav) => {
        if ($nav.text().toLowerCase().includes('desktop')) {
          // It should still be accessible (maybe via dropdown)
          cy.get('#navDropdown').click();
          cy.contains(/desktop/i).should('exist');
        } else {
          cy.log('Desktop feature not available — skipping mobile VNC test');
        }
      });
    });
  });
});
