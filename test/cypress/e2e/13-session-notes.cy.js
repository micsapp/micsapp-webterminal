/// <reference types="cypress" />

describe('Session Notes', () => {
  beforeEach(() => {
    cy.visitApp();
    cy.get('.navbar', { timeout: 15000 }).should('be.visible');
  });

  it('opens a mobile-friendly note editor beside Quick Commands', () => {
    cy.viewport(375, 667);
    cy.get('#sessionsBtn').click();
    cy.get('#sessionsModal').should('be.visible');
    cy.get('#sessSendDefaultBtn').should('contain.text', 'Send to active');
    cy.get('#sessNoteBtn').click();
    cy.get('#sessNotesPopover').should('be.visible').and('have.class', 'open');
    cy.get('#sessNoteSendDefaultBtn').should('contain.text', 'Send to active');
    cy.get('#sessNoteVoiceBtn')
      .should('be.visible')
      .and('have.attr', 'aria-label', 'Start voice input')
      .and('have.attr', 'aria-pressed', 'false');
    cy.get('#sessNoteContent')
      .should('be.visible')
      .and('have.attr', 'autocorrect', 'off')
      .and('have.attr', 'spellcheck', 'false');
    cy.get('#sessNotesPopover').then(($popover) => {
      const rect = $popover[0].getBoundingClientRect();
      expect(getComputedStyle($popover[0]).position).to.equal('fixed');
      expect(rect.top).to.be.at.least(0);
      expect(rect.bottom).to.be.at.most(Cypress.config('viewportHeight') + 1);
      expect(rect.height).to.be.greaterThan(600);
    });
  });

  it('dictates speech into the note at the cursor and can stop listening', () => {
    cy.window().then((win) => {
      win.SpeechRecognition = class FakeSpeechRecognition {
        start() {
          this.onresult({ results: [[{ transcript: 'voice text' }]] });
        }
        stop() { this.onend(); }
        abort() { this.onend(); }
      };
      win.sessNoteVoiceInit();
    });

    cy.get('#sessionsBtn').click();
    cy.get('#sessNoteBtn').click();
    cy.get('#sessNoteContent').clear().type('before after').then(($content) => {
      $content[0].setSelectionRange(6, 6);
    });
    cy.get('#sessNoteVoiceBtn').click().should('have.attr', 'aria-pressed', 'true');
    cy.get('#sessNoteContent').should('have.value', 'before voice text after');
    cy.get('#sessNoteVoiceBtn').click().should('have.attr', 'aria-pressed', 'false');
  });

  it('adds, updates, lists, and deletes a persistent note', () => {
    cy.loginViaApi();
    const title = `Cypress note ${Date.now()}`;
    let noteId;

    cy.request('POST', '/api/notes', {
      action: 'add',
      title,
      content: 'echo original note'
    }).then((response) => {
      expect(response.body).to.have.property('ok', true);
      noteId = response.body.id;
      return cy.request('POST', '/api/notes', {
        action: 'update',
        id: noteId,
        title,
        content: 'echo updated note'
      });
    }).then((response) => {
      expect(response.body).to.have.property('ok', true);
      return cy.request('/api/notes');
    }).then((response) => {
      const saved = response.body.notes.find(note => note.id === noteId);
      expect(saved).to.include({
        id: noteId,
        title,
        content: 'echo updated note'
      });
      expect(saved.created).to.be.a('number');
      expect(saved.updated).to.be.a('number');
      return cy.request('POST', '/api/notes', { action: 'delete', id: noteId });
    }).then((response) => {
      expect(response.body).to.have.property('ok', true);
    });
  });
});
