/// <reference types="cypress" />

describe('Session Notes', () => {
  beforeEach(() => {
    cy.visitApp();
    cy.get('.navbar', { timeout: 15000 }).should('be.visible');
  });

  it('opens a mobile-friendly note editor beside Quick Commands', () => {
    cy.get('#sessionsBtn').click();
    cy.get('#sessionsModal').should('be.visible');
    cy.get('#sessSendDefaultBtn').should('contain.text', 'Send to active');
    cy.get('#sessNoteBtn').click();
    cy.get('#sessNotesPopover').should('be.visible').and('have.class', 'open');
    cy.get('#sessNoteSendDefaultBtn').should('contain.text', 'Send to active');
    cy.get('#sessNoteContent')
      .should('be.visible')
      .and('have.attr', 'autocorrect', 'off')
      .and('have.attr', 'spellcheck', 'false');
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
