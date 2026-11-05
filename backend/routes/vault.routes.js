import express from 'express';
import multer from 'multer';
import { VaultController } from '../controllers/vault.controller.js';
import { requireSessionAuth } from '../middleware/sessionAuth.middleware.js';
import { config } from '../config/config.js';

const router = express.Router();

// Memory storage for multer: processes encrypted blob directly in memory
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxFileSizeMB * 1024 * 1024 // e.g. 50 MB
  }
});

// Vault Routes with authentication & ownership isolation
router.get('/status', VaultController.status);
router.post('/upload', requireSessionAuth, upload.single('encryptedFile'), VaultController.upload);
router.get('/documents', requireSessionAuth, VaultController.list);
router.get('/download/:id', requireSessionAuth, VaultController.download);
router.delete('/documents/:id', requireSessionAuth, VaultController.delete);

export default router;

