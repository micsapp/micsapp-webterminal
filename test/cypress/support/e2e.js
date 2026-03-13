// ***********************************************
// Custom commands and global hooks for
// micsapp-webterminal E2E tests
// ***********************************************

// ─── Login Command ───────────────────────────────────
Cypress.Commands.add('login', (username, password) => {
  const user = username || Cypress.env('TEST_USERNAME');
  const pass = password || Cypress.env('TEST_PASSWORD');

  cy.session([user, pass], () => {
    cy.visit('/login');
    cy.get('#username').clear().type(user);
    cy.get('#password').clear().type(pass);
    cy.get('form#form button[type="submit"]').click();
    cy.url().should('not.include', '/login');
    cy.getCookie(Cypress.env('COOKIE_NAME')).should('exist');
  });
});

// ─── Login via API (faster, no UI) ──────────────────
Cypress.Commands.add('loginViaApi', (username, password) => {
  const user = username || Cypress.env('TEST_USERNAME');
  const pass = password || Cypress.env('TEST_PASSWORD');

  cy.session([user, pass, 'api'], () => {
    cy.request({
      method: 'POST',
      url: '/api/login',
      body: { username: user, password: pass },
      headers: { 'Content-Type': 'application/json' },
    }).then((resp) => {
      expect(resp.status).to.eq(200);
      expect(resp.body).to.have.property('ok', true);
      expect(resp.body).to.have.property('port');
    });
  });
});

// ─── Visit app (authenticated) ──────────────────────
Cypress.Commands.add('visitApp', () => {
  cy.loginViaApi();
  cy.visit('/');
  cy.get('.navbar', { timeout: 15000 }).should('be.visible');
});

// ─── Get active tab ──────────────────────────────────
Cypress.Commands.add('getActiveTab', () => {
  return cy.get('.tab-bar .tab.active');
});

// ─── Get terminal container ──────────────────────────
Cypress.Commands.add('getTermContainer', () => {
  return cy.get('#termContainer');
});

// ─── Wait for terminal iframe to load ───────────────
Cypress.Commands.add('waitForTerminal', (timeout = 15000) => {
  cy.get('#termContainer iframe', { timeout }).should('exist');
});

// ─── Toggle file panel ──────────────────────────────
Cypress.Commands.add('openFilePanel', () => {
  cy.get('#filePanel').then(($panel) => {
    if (!$panel.hasClass('open')) {
      cy.get('#filesBtn').click({ force: true });
    }
  });
  cy.get('#filePanel.open').should('be.visible');
});

Cypress.Commands.add('closeFilePanel', () => {
  cy.get('#filePanel').then(($panel) => {
    if ($panel.hasClass('open')) {
      cy.get('#filesBtn').click({ force: true });
    }
  });
  cy.get('#filePanel').should('not.have.class', 'open');
});

// ─── Open Settings Panel ────────────────────────────
Cypress.Commands.add('openSettings', () => {
  cy.get('#settingsPanel').then(($panel) => {
    if (!$panel.hasClass('open')) {
      cy.get('#settingsBtn').click({ force: true });
    }
  });
  cy.get('#settingsPanel.open').should('be.visible');
});

// ─── Open Theme Panel ───────────────────────────────
Cypress.Commands.add('openThemes', () => {
  cy.get('#themePanel').then(($panel) => {
    if (!$panel.hasClass('open')) {
      cy.get('#themeBtn').click({ force: true });
    }
  });
  cy.get('#themePanel.open').should('be.visible');
});

// ─── Open Quick Commands ────────────────────────────
Cypress.Commands.add('openQuickCommands', () => {
  cy.get('#cmdsBtn').click({ force: true });
  cy.get('#qcOverlay.open').should('be.visible');
});

// ─── Close all modals/overlays ──────────────────────
Cypress.Commands.add('closeAllModals', () => {
  cy.get('body').type('{esc}');
  cy.wait(300);
});

// ─── API request with auth cookie ───────────────────
Cypress.Commands.add('apiRequest', (method, url, body) => {
  const opts = { method, url, failOnStatusCode: false };
  if (body) opts.body = body;
  return cy.request(opts);
});

// ─── Prevent uncaught exception failures ────────────
Cypress.on('uncaught:exception', (err) => {
  // WebSocket close errors are expected during test navigation
  if (err.message.includes('WebSocket') ||
      err.message.includes('ResizeObserver') ||
      err.message.includes('Script error')) {
    return false;
  }
});
