import { encryptDocument, decryptDocument, DecryptionError } from './crypto.js';
import { checkPassphraseBreach } from './breach-check.js';
import { VaultAPI } from './api.js';
import { ClientSessionState } from './storage.js';
import { UIManager } from './ui.js';

let selectedFile = null;
let currentDocuments = [];
let pendingDecryptDocId = null;

// ─── Session Check & Auth Guard ─────────────────────────────────
async function checkSession() {
  try {
    const res = await fetch('/api/auth/me', { credentials: 'include' });
    const data = await res.json();
    if (!data.authenticated) {
      window.location.href = '/login.html';
      return null;
    }
    return data.user;
  } catch {
    window.location.href = '/login.html';
    return null;
  }
}

function handleSessionExpired() {
  UIManager.showToast('Session expired. Redirecting to sign in...', 'warning');
  setTimeout(() => { window.location.href = '/login.html'; }, 1500);
}

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
  const user = await checkSession();
  if (!user) return; // Redirect already triggered

  // Inject user info and logout button into header
  renderUserHeader(user);

  // Fetch CSRF token for vault mutations
  await VaultAPI.refreshCsrfToken();

  setupEventListeners();
  loadSettings();
  await refreshStorageStatus();
  await refreshDocuments();
});

function renderUserHeader(user) {
  const headerStatus = document.querySelector('.header-status');
  if (!headerStatus) return;

  // Insert user info before existing children
  const userGroup = document.createElement('div');
  userGroup.className = 'user-info-group';
  userGroup.innerHTML = `
    <div class="user-display">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
      <strong>${UIManager.escapeHTML(user.fullName || user.username)}</strong>
    </div>
    <button id="logout-btn" class="btn-logout" title="Sign out and clear session">Logout</button>
  `;
  headerStatus.insertBefore(userGroup, headerStatus.firstChild);

  // Logout handler
  document.getElementById('logout-btn')?.addEventListener('click', handleLogout);
}

async function handleLogout() {
  try {
    const csrfToken = await VaultAPI.refreshCsrfToken();
    const res = await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken || ''
      }
    });

    // Clear any in-memory passphrase references (zero-knowledge cleanup)
    selectedFile = null;
    currentDocuments = [];
    pendingDecryptDocId = null;

    // Clear passphrase input values
    const passInput = document.getElementById('upload-passphrase');
    if (passInput) passInput.value = '';
    const decryptPass = document.getElementById('decrypt-passphrase');
    if (decryptPass) decryptPass.value = '';

    window.location.href = '/login.html';
  } catch {
    window.location.href = '/login.html';
  }
}

function setupEventListeners() {
  // File Dropzone
  const dropzone = document.getElementById('file-dropzone');
  const fileInput = document.getElementById('file-input');

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => handleFileSelected(e.target.files[0]));

    ['dragenter', 'dragover'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-active');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropzone.addEventListener(eventName, (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-active');
      });
    });

    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelected(e.dataTransfer.files[0]);
      }
    });
  }

  // Passphrase visibility toggle
  const togglePassBtn = document.getElementById('toggle-passphrase-btn');
  const passInput = document.getElementById('upload-passphrase');
  if (togglePassBtn && passInput) {
    togglePassBtn.addEventListener('click', () => {
      const isPassword = passInput.type === 'password';
      passInput.type = isPassword ? 'text' : 'password';
      togglePassBtn.textContent = isPassword ? 'Hide' : 'Show';
    });
  }

  // Passphrase Breach Check on blur or debounce
  let breachDebounce = null;
  if (passInput) {
    passInput.addEventListener('input', () => {
      clearTimeout(breachDebounce);
      breachDebounce = setTimeout(triggerBreachCheck, 600);
    });
  }

  // Encrypt & Upload Form
  const uploadForm = document.getElementById('vault-upload-form');
  if (uploadForm) {
    uploadForm.addEventListener('submit', handleEncryptAndUpload);
  }

  // Decryption Modal controls
  const decryptModal = document.getElementById('decrypt-modal');
  const decryptForm = document.getElementById('decrypt-form');
  const cancelDecryptBtn = document.getElementById('cancel-decrypt-btn');
  const toggleDecryptPassBtn = document.getElementById('toggle-decrypt-pass-btn');
  const decryptPassInput = document.getElementById('decrypt-passphrase');

  if (cancelDecryptBtn && decryptModal) {
    cancelDecryptBtn.addEventListener('click', () => {
      decryptModal.style.display = 'none';
      if (decryptPassInput) decryptPassInput.value = '';
      pendingDecryptDocId = null;
    });
  }

  if (toggleDecryptPassBtn && decryptPassInput) {
    toggleDecryptPassBtn.addEventListener('click', () => {
      const isPassword = decryptPassInput.type === 'password';
      decryptPassInput.type = isPassword ? 'text' : 'password';
      toggleDecryptPassBtn.textContent = isPassword ? 'Hide' : 'Show';
    });
  }

  if (decryptForm) {
    decryptForm.addEventListener('submit', handleExecuteDecrypt);
  }

  // Settings modal
  const openSettingsBtn = document.getElementById('open-settings-btn');
  const closeSettingsBtn = document.getElementById('close-settings-btn');
  const settingsModal = document.getElementById('settings-modal');
  const saveSettingsBtn = document.getElementById('save-settings-btn');

  if (openSettingsBtn && settingsModal) {
    openSettingsBtn.addEventListener('click', () => settingsModal.style.display = 'flex');
  }
  if (closeSettingsBtn && settingsModal) {
    closeSettingsBtn.addEventListener('click', () => settingsModal.style.display = 'none');
  }
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', handleSaveSettings);
  }

  // Refresh button
  const refreshBtn = document.getElementById('refresh-vault-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await refreshStorageStatus();
      await refreshDocuments();
      UIManager.showToast('Vault synchronized with backend', 'info');
    });
  }
}

function handleFileSelected(file) {
  if (!file) return;

  const maxSize = 50 * 1024 * 1024; // 50MB
  if (file.size > maxSize) {
    UIManager.showToast(`File size (${UIManager.formatBytes(file.size)}) exceeds maximum allowed 50 MB.`, 'error');
    return;
  }

  selectedFile = file;

  const nameEl = document.getElementById('selected-file-name');
  const sizeEl = document.getElementById('selected-file-size');
  const fileDetails = document.getElementById('selected-file-details');

  if (nameEl) nameEl.textContent = file.name;
  if (sizeEl) sizeEl.textContent = `Size: ${UIManager.formatBytes(file.size)} (${file.type || 'unknown type'})`;
  if (fileDetails) fileDetails.style.display = 'flex';
}

async function triggerBreachCheck() {
  const passInput = document.getElementById('upload-passphrase');
  const badge = document.getElementById('breach-status-badge');
  if (!passInput || !badge) return;

  const passphrase = passInput.value;
  if (!passphrase || passphrase.length < 4) {
    badge.style.display = 'none';
    return;
  }

  if (!ClientSessionState.isBreachCheckEnabled()) {
    badge.style.display = 'none';
    return;
  }

  badge.style.display = 'inline-flex';
  badge.className = 'breach-badge badge-checking';
  badge.innerHTML = `<span class="spinner-small"></span> Checking known breaches...`;

  const result = await checkPassphraseBreach(passphrase);

  if (result.breached) {
    badge.className = 'breach-badge badge-breached';
    badge.innerHTML = `⚠️ Pwned! Found in ${result.count.toLocaleString()} breaches. Choose a safer passphrase.`;
  } else if (result.checked) {
    badge.className = 'breach-badge badge-safe';
    badge.innerHTML = `✓ No matches in HIBP database`;
  } else {
    badge.className = 'breach-badge badge-unavailable';
    badge.innerHTML = `ℹ Breach API unavailable (Proceed with care)`;
  }
}

async function handleEncryptAndUpload(e) {
  e.preventDefault();

  if (!selectedFile) {
    UIManager.showToast('Please select a KYC document to encrypt.', 'warning');
    return;
  }

  const passInput = document.getElementById('upload-passphrase');
  const passphrase = passInput ? passInput.value : '';

  if (!passphrase || passphrase.length < 8) {
    UIManager.showToast('Passphrase must be at least 8 characters for strong key derivation.', 'warning');
    return;
  }

  const submitBtn = document.getElementById('encrypt-upload-btn');
  if (submitBtn) submitBtn.disabled = true;

  try {
    UIManager.updateProgress(10, 0, 'Reading document into secure browser memory...');
    const fileBuffer = await selectedFile.arrayBuffer();

    const iterations = ClientSessionState.getIterations();
    UIManager.updateProgress(40, 0, `Deriving AES-256 key (PBKDF2, ${iterations.toLocaleString()} iter) & encrypting...`);

    // Client-side encryption
    const { ciphertextBuffer, metadata } = await encryptDocument(
      fileBuffer,
      passphrase,
      {
        filename: selectedFile.name,
        mimeType: selectedFile.type || 'application/octet-stream'
      },
      { iterations }
    );

    UIManager.updateProgress(80, 20, 'Transmitting ciphertext to zero-knowledge vault...');

    const result = await VaultAPI.uploadEncrypted(
      ciphertextBuffer,
      metadata,
      null, // userId no longer needed — session handles identity
      (uploadPercent) => {
        UIManager.updateProgress(80, uploadPercent, `Uploading ciphertext (${uploadPercent}%)...`);
      }
    );

    UIManager.updateProgress(100, 100, 'Upload complete! Ciphertext secured.');
    UIManager.showToast('KYC document successfully encrypted and stored!', 'success');

    // Reset upload form & purge sensitive references
    selectedFile = null;
    passInput.value = '';
    const fileInput = document.getElementById('file-input');
    if (fileInput) fileInput.value = '';
    const fileDetails = document.getElementById('selected-file-details');
    if (fileDetails) fileDetails.style.display = 'none';
    const breachBadge = document.getElementById('breach-status-badge');
    if (breachBadge) breachBadge.style.display = 'none';

    setTimeout(() => {
      UIManager.resetProgress();
    }, 1500);

    await refreshDocuments();
  } catch (err) {
    if (err.message === 'SESSION_EXPIRED') return handleSessionExpired();
    console.error('[Upload Error]', err);
    UIManager.showToast(err.message || 'Failed to encrypt or upload document.', 'error');
    UIManager.resetProgress();
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

function handleDecryptClick(docId) {
  pendingDecryptDocId = docId;
  const modal = document.getElementById('decrypt-modal');
  const passInput = document.getElementById('decrypt-passphrase');
  const docInfoEl = document.getElementById('modal-doc-info');

  const targetDoc = currentDocuments.find(d => d.docId === docId);
  if (docInfoEl && targetDoc) {
    docInfoEl.textContent = `File: ${targetDoc.originalFilename} (${UIManager.formatBytes(targetDoc.fileSize)})`;
  }

  if (modal) modal.style.display = 'flex';
  if (passInput) {
    passInput.value = '';
    passInput.focus();
  }
}

async function handleExecuteDecrypt(e) {
  e.preventDefault();
  if (!pendingDecryptDocId) return;

  const passInput = document.getElementById('decrypt-passphrase');
  const passphrase = passInput ? passInput.value : '';

  if (!passphrase) {
    UIManager.showToast('Please enter the decryption passphrase.', 'warning');
    return;
  }

  const modal = document.getElementById('decrypt-modal');
  const decryptBtn = document.getElementById('confirm-decrypt-btn');
  const errorAlert = document.getElementById('modal-decrypt-error');

  if (errorAlert) errorAlert.style.display = 'none';
  if (decryptBtn) {
    decryptBtn.disabled = true;
    decryptBtn.textContent = 'Decrypting...';
  }

  try {
    // Download raw ciphertext and headers (no userId needed)
    const { ciphertextBuffer, metadata } = await VaultAPI.downloadEncrypted(pendingDecryptDocId);

    // Decrypt locally using Web Crypto API
    const decrypted = await decryptDocument(ciphertextBuffer, passphrase, metadata);

    UIManager.showToast(`✓ Document "${decrypted.filename}" successfully decrypted and verified!`, 'success');

    // Trigger local browser download of reconstructed plaintext
    const downloadUrl = URL.createObjectURL(decrypted.blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = decrypted.filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(downloadUrl);
      a.remove();
    }, 1000);

    // Close modal & reset
    if (modal) modal.style.display = 'none';
    if (passInput) passInput.value = '';
    pendingDecryptDocId = null;
  } catch (err) {
    if (err.message === 'SESSION_EXPIRED') return handleSessionExpired();
    console.error('[Decryption Failed]', err);
    if (errorAlert) {
      errorAlert.textContent = err.message || 'Decryption failed: Incorrect passphrase or tampered ciphertext.';
      errorAlert.style.display = 'block';
    } else {
      UIManager.showToast(err.message, 'error');
    }
  } finally {
    if (decryptBtn) {
      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Unlock & Decrypt';
    }
  }
}

async function handleDeleteClick(docId) {
  const targetDoc = currentDocuments.find(d => d.docId === docId);
  const name = targetDoc ? targetDoc.originalFilename : 'this document';

  const confirmed = confirm(`Are you sure you want to permanently delete "${name}" from the vault?\n\nThis will remove the ciphertext and metadata from cloud storage.`);
  if (!confirmed) return;

  try {
    await VaultAPI.deleteDocument(docId);
    UIManager.showToast(`Document "${name}" deleted.`, 'info');
    await refreshDocuments();
  } catch (err) {
    if (err.message === 'SESSION_EXPIRED') return handleSessionExpired();
    UIManager.showToast(err.message || 'Failed to delete document.', 'error');
  }
}

async function refreshDocuments() {
  try {
    const res = await VaultAPI.listDocuments();
    currentDocuments = res.documents || [];
    UIManager.renderDocumentsList(currentDocuments, handleDecryptClick, handleDeleteClick);

    const countEl = document.getElementById('vault-doc-count');
    if (countEl) countEl.textContent = `${currentDocuments.length} Document${currentDocuments.length === 1 ? '' : 's'}`;
  } catch (err) {
    if (err.message === 'SESSION_EXPIRED') return handleSessionExpired();
    console.error('[Fetch Documents Error]', err);
    UIManager.showToast('Unable to load documents from vault.', 'error');
  }
}

async function refreshStorageStatus() {
  try {
    const data = await VaultAPI.getStatus();
    if (data.storage) {
      UIManager.renderStorageStatus(data.storage);
    }
  } catch (err) {
    console.warn('[Storage Status Check Failed]', err);
  }
}

function loadSettings() {
  const iterSelect = document.getElementById('setting-iterations');
  const breachToggle = document.getElementById('setting-breach-check');

  if (iterSelect) iterSelect.value = ClientSessionState.getIterations();
  if (breachToggle) breachToggle.checked = ClientSessionState.isBreachCheckEnabled();
}

function handleSaveSettings() {
  const iterSelect = document.getElementById('setting-iterations');
  const breachToggle = document.getElementById('setting-breach-check');
  const modal = document.getElementById('settings-modal');

  if (iterSelect) ClientSessionState.setIterations(parseInt(iterSelect.value, 10));
  if (breachToggle) ClientSessionState.setBreachCheckEnabled(breachToggle.checked);

  if (modal) modal.style.display = 'none';
  UIManager.showToast('Vault settings saved.', 'success');
  refreshDocuments();
}
