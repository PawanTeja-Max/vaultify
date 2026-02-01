const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Configuration
const ENCRYPTION_KEY = crypto.randomBytes(32); // In production, use a persistent 32-byte key
const IV_LENGTH = 16;
const VAULT_DIR = path.join(__dirname, 'vault');
const LOGS = [];

if (!fs.existsSync(VAULT_DIR)) fs.mkdirSync(VAULT_DIR);

app.use(cors());
app.use(express.json());

// --- Encryption Helper ---
function encrypt(buffer) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return { iv: iv.toString('hex'), data: encrypted.toString('hex') };
}

// --- Decryption Helper ---
function decrypt(encryptedData, ivHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const encryptedText = Buffer.from(encryptedData, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    return Buffer.concat([decipher.update(encryptedText), decipher.final()]);
}

// --- API Endpoints ---

// 1. Upload & Encrypt
const upload = multer({ storage: multer.memoryStorage() });
app.post('/api/upload', upload.single('file'), (req, res) => {
    try {
        const encrypted = encrypt(req.file.buffer);
        const secureName = `${Date.now()}-${req.file.originalname}.dat`;
        
        // Store metadata and IV (In production, use a DB)
        const metaData = {
            originalName: req.file.originalname,
            iv: encrypted.iv,
            data: encrypted.data
        };
        
        fs.writeFileSync(path.join(VAULT_DIR, secureName), JSON.stringify(metaData));
        
        LOGS.unshift({ event: `File Uploaded: ${req.file.originalname}`, status: 'SUCCESS', timestamp: new Date() });
        res.json({ success: true });
    } catch (err) {
        LOGS.unshift({ event: 'Upload Failed', status: 'FAILURE', timestamp: new Date() });
        res.status(500).json({ error: 'Encryption failed' });
    }
});

// 2. List Files
app.get('/api/files', (req, res) => {
    const files = fs.readdirSync(VAULT_DIR).map(file => {
        const content = JSON.parse(fs.readFileSync(path.join(VAULT_DIR, file)));
        return { display: content.originalName, secure: file };
    });
    res.json(files);
});

// 3. Decrypt & Download
app.get('/api/download/:filename', (req, res) => {
    try {
        const filePath = path.join(VAULT_DIR, req.params.filename);
        const encryptedContent = JSON.parse(fs.readFileSync(filePath));
        const decryptedBuffer = decrypt(encryptedContent.data, encryptedContent.iv);
        
        res.setHeader('Content-Disposition', `attachment; filename=${encryptedContent.originalName}`);
        res.send(decryptedBuffer);
        
        LOGS.unshift({ event: `Decrypted: ${encryptedContent.originalName}`, status: 'SUCCESS', timestamp: new Date() });
    } catch (err) {
        res.status(500).send('Decryption failed');
    }
});

// 4. Logs
app.get('/api/logs', (req, res) => res.json(LOGS.slice(0, 10)));

app.listen(PORT, () => console.log(`Vaultify Backend running on http://localhost:${PORT}`));