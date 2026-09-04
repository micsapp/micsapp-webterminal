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

  it('shows Notes as a stable desktop subview instead of overlapping Sessions', () => {
    cy.get('#sessionsBtn').click();
    cy.get('#sessNoteBtn').click();
    cy.get('#sessionsModal').should('have.class', 'sess-notes-mode');
    cy.get('#sessionsModal > .fp-modal > .fp-modal-header').should('not.be.visible');
    cy.get('#sessionsModal > .fp-modal > .fp-modal-body').should('not.be.visible');
    cy.get('#sessNotesPopover').should('be.visible').then(($notes) => {
      const noteRect = $notes[0].getBoundingClientRect();
      const modalRect = $notes[0].closest('.fp-modal').getBoundingClientRect();
      expect(noteRect.left).to.be.at.least(modalRect.left);
      expect(noteRect.right).to.be.at.most(modalRect.right + 1);
      expect(noteRect.top).to.be.at.least(modalRect.top);
      expect(noteRect.bottom).to.be.at.most(modalRect.bottom + 1);
    });
    cy.get('#sessNotesPopover .sess-notes-header button[aria-label="Close notes"]').click();
    cy.get('#sessionsModal').should('not.have.class', 'sess-notes-mode');
    cy.get('#sessionsModal > .fp-modal > .fp-modal-body').should('be.visible');
  });

  it('uses the original live browser dictation on desktop', () => {
    cy.window().then((win) => {
      win.SpeechRecognition = class FakeSpeechRecognition {
        start() {
          this.onresult({ results: [[{ transcript: 'desktop voice' }]] });
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
    cy.get('#sessNoteContent').should('have.value', 'before desktop voice after');
    cy.get('#sessNoteVoiceBtn').click().should('have.attr', 'aria-pressed', 'false');
  });

  it('automatically transcribes ordered mobile batches after silence and keeps listening', () => {
    let requestCount = 0;
    cy.intercept('POST', '/api/transcribe', (req) => {
      expect(req.headers['content-type']).to.include('audio/webm');
      const text = requestCount++ === 0 ? 'mobile voice batch' : '';
      req.reply({ statusCode: 200, body: { ok: true, text, language: 'en' } });
    }).as('transcribeVoice');
    cy.window().then((win) => {
      const stream = { getTracks: () => [{ stop() {} }] };
      Object.defineProperty(win.navigator, 'userAgent', {
        configurable: true,
        value: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Mobile'
      });
      Object.defineProperty(win.navigator, 'mediaDevices', {
        configurable: true,
        value: { getUserMedia: () => Promise.resolve(stream) }
      });
      let levelReads = 0;
      win.AudioContext = class FakeAudioContext {
        createAnalyser() {
          return {
            fftSize: 512,
            smoothingTimeConstant: 0,
            getByteTimeDomainData(data) {
              data.fill(levelReads++ < 3 ? 180 : 128);
            }
          };
        }
        createMediaStreamSource() { return { connect() {} }; }
        resume() { return Promise.resolve(); }
        close() { return Promise.resolve(); }
      };
      win.requestAnimationFrame = (callback) => {
        win.__voiceFrame = callback;
        return 1;
      };
      win.cancelAnimationFrame = () => {};
      win.MediaRecorder = class FakeMediaRecorder {
        static isTypeSupported(type) { return type.startsWith('audio/webm'); }
        constructor() {
          this.mimeType = 'audio/webm;codecs=opus';
          this.state = 'inactive';
        }
        start() { this.state = 'recording'; }
        stop() {
          this.state = 'inactive';
          this.ondataavailable({ data: new win.Blob(['recorded audio'], { type: 'audio/webm' }) });
          this.onstop();
        }
      };
      win.sessNoteVoiceInit();
    });

    cy.viewport(375, 667);
    cy.get('#sessionsBtn').click();
    cy.get('#sessNoteBtn').click();
    cy.get('#sessNoteContent').clear().type('before after').then(($content) => {
      $content[0].setSelectionRange(6, 6);
    });
    cy.get('#sessNoteVoiceBtn').click().should('have.attr', 'aria-pressed', 'true');
    cy.window().then((win) => win.__voiceFrame());
    cy.window().then((win) => win.__voiceFrame());
    cy.wait(1700);
    cy.window().then((win) => win.__voiceFrame());
    cy.wait('@transcribeVoice');
    cy.get('#sessNoteContent').should('have.value', 'before mobile voice batch after');
    cy.get('#sessNoteVoiceBtn').should('have.attr', 'aria-pressed', 'true');
    cy.get('#sessNoteVoiceBtn').click();
    cy.wait('@transcribeVoice');
    cy.get('#sessNoteVoiceBtn').should('have.attr', 'aria-pressed', 'false').and('not.be.disabled');
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
