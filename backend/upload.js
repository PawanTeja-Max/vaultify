const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs-extra');
const cors = require('cors');
const path = require('path');

const app = express();
const upload = multer({ dest: 'temp/' }); // Temporary storage before encryption

app.use(cors());
app.use(express.json());

// --- Security Configuration ---
const ENCRYPTION_KEY = crypto.randomBytes(32); // In production, store this in a .env file
const IV_LENGTH = 16; 

// --- Encryption Logic ---
function encrypt(buffer) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return Buffer.concat([iv, encrypted]); // Prepend IV for decryption later
}

// --- API Routes ---

// 1. Upload & Encrypt
app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        const fileContent = await fs.readFile(req.file.path);
        const encryptedContent = encrypt(fileContent);
        
        const fileName = `${Date.now()}-${req.file.originalname}.enc`;
        await fs.outputFile(path.join(__dirname, 'vault', fileName), encryptedContent);
        await fs.remove(req.file.path); // Clean up temp file

        res.json({ 
            success: true, 
            message: "File encrypted and vaulted successfully",
            traceId: `TR-${Math.floor(Math.random() * 9000) + 1000}`
        });
    } catch (err) {
        res.status(500).json({ error: "Encryption failed" });
    }
});

// 2. Simple Audit Log Endpoint
app.get('/api/logs', (req, res) => {
    res.json([
        { id: 1, event: 'VAULT_INIT', status: 'SUCCESS', timestamp: new Date() },
        { id: 2, event: 'ENCRYPTION_KEY_GEN', status: 'SUCCESS', timestamp: new Date() }
    ]);
});

app.listen(3000, () => console.log('Vaultify Backend running on port 3000'));