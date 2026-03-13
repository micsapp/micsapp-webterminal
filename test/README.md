# E2E Test Suite — micsapp-webterminal

Comprehensive Cypress end-to-end tests covering **all** application functions.

## Quick Start

```bash
cd test
npm install
```

## Running Tests

### Headless (all specs)

```bash
npm test                 # runs all specs headless
```

### Interactive (Cypress GUI)

```bash
npm run cy:open          # opens Cypress test runner
```

### Individual Suites

```bash
npm run cy:run:auth       # 01 — Authentication & sessions
npm run cy:run:spa        # 02 — SPA loading & layout
npm run cy:run:tabs       # 03 — Tab management
npm run cy:run:split      # 04 — Split panes
npm run cy:run:settings   # 05 — Settings & themes
npm run cy:run:files      # 06 — File browser
npm run cy:run:commands   # 07 — Quick commands
npm run cy:run:keyboard   # 08 — Keyboard shortcuts
npm run cy:run:security   # 09 — Security
npm run cy:run:mobile     # 10 — Mobile / responsive
npm run cy:run:api        # 11 — API endpoints
npm run cy:run:desktop    # 12 — Desktop / VNC
```

## Configuration

| Environment Variable    | Default                              | Description                        |
|-------------------------|--------------------------------------|------------------------------------|
| `CYPRESS_BASE_URL`      | `https://micsmac-ssh.micstec.com`    | Target application URL             |
| `CYPRESS_TEST_USERNAME` | `testuser`                           | Login username for tests           |
| `CYPRESS_TEST_PASSWORD` | `testpass`                           | Login password for tests           |

Override at runtime:

```bash
CYPRESS_BASE_URL=http://localhost:7680 \
CYPRESS_TEST_USERNAME=myuser \
CYPRESS_TEST_PASSWORD=mypass \
npm test
```

## Test Coverage Map

| Spec File                       | PRD Requirements                              |
|---------------------------------|-----------------------------------------------|
| `01-authentication.cy.js`       | AUTH-01 → AUTH-09                              |
| `02-spa-loading.cy.js`          | TERM-01, TERM-02, TERM-04                     |
| `03-tabs.cy.js`                 | TAB-01 → TAB-07                               |
| `04-split-panes.cy.js`          | SPLIT-01 → SPLIT-08                           |
| `05-settings-themes.cy.js`      | SET-01 → SET-04, THEME-01 → THEME-03          |
| `06-file-browser.cy.js`         | FILE-01 → FILE-11                             |
| `07-quick-commands.cy.js`       | CMD-01 → CMD-05                               |
| `08-keyboard-shortcuts.cy.js`   | TAB-07, SPLIT-08                              |
| `09-security.cy.js`             | SEC-01 → SEC-06                               |
| `10-mobile.cy.js`               | MOB-01 → MOB-05                               |
| `11-api-endpoints.cy.js`        | All GET/POST routes from auth.py              |
| `12-desktop-vnc.cy.js`          | VNC-01 → VNC-03                               |

## Project Structure

```
test/
├── cypress.config.js          # Cypress configuration
├── package.json               # Dependencies & npm scripts
├── README.md                  # This file
└── cypress/
    ├── support/
    │   └── e2e.js             # Custom commands & global hooks
    └── e2e/
        ├── 01-authentication.cy.js
        ├── 02-spa-loading.cy.js
        ├── 03-tabs.cy.js
        ├── 04-split-panes.cy.js
        ├── 05-settings-themes.cy.js
        ├── 06-file-browser.cy.js
        ├── 07-quick-commands.cy.js
        ├── 08-keyboard-shortcuts.cy.js
        ├── 09-security.cy.js
        ├── 10-mobile.cy.js
        ├── 11-api-endpoints.cy.js
        └── 12-desktop-vnc.cy.js
```
