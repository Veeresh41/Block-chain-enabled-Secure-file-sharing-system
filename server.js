const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// ===================== BLOCKCHAIN =====================
class Block {
    constructor(index, timestamp, data, previousHash = '') {
        this.index = index;
        this.timestamp = timestamp;
        this.data = data;
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = this.computeHash();
    }

    computeHash() {
        const content = JSON.stringify({
            index: this.index,
            timestamp: this.timestamp,
            data: this.data,
            previousHash: this.previousHash,
            nonce: this.nonce
        });
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    // Simple proof-of-work (difficulty=2 for speed)
    mineBlock(difficulty = 2) {
        const target = '0'.repeat(difficulty);
        while (!this.hash.startsWith(target)) {
            this.nonce++;
            this.hash = this.computeHash();
        }
    }
}

class Blockchain {
    constructor(chainPath) {
        this.chainPath = chainPath;
        this.chain = this.loadChain();
        if (this.chain.length === 0) {
            this.chain.push(this.createGenesisBlock());
            this.saveChain();
        }
    }

    createGenesisBlock() {
        const genesis = new Block(0, new Date().toISOString(), { type: 'GENESIS', message: 'SecureShare Blockchain Initialized' }, '0');
        genesis.mineBlock();
        return genesis;
    }

    loadChain() {
        try {
            if (fs.existsSync(this.chainPath)) {
                const raw = fs.readFileSync(this.chainPath, 'utf-8');
                return JSON.parse(raw);
            }
        } catch { }
        return [];
    }

    saveChain() {
        fs.writeFileSync(this.chainPath, JSON.stringify(this.chain, null, 2));
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    addBlock(data) {
        const prev = this.getLatestBlock();
        const block = new Block(prev.index + 1, new Date().toISOString(), data, prev.hash);
        block.mineBlock(2);
        this.chain.push(block);
        this.saveChain();
        return block;
    }

    isChainValid() {
        for (let i = 1; i < this.chain.length; i++) {
            const current = this.chain[i];
            const previous = this.chain[i - 1];

            // Recompute hash to verify integrity
            const recomputed = new Block(
                current.index, current.timestamp, current.data, current.previousHash
            );
            recomputed.nonce = current.nonce;

            if (current.hash !== recomputed.computeHash()) return false;
            if (current.previousHash !== previous.hash) return false;
        }
        return true;
    }

    getBlockByFilename(filename) {
        return this.chain.find(b => b.data && b.data.filename === filename) || null;
    }
}

const blockchain = new Blockchain(path.join(__dirname, 'blockchain.json'));

// ===================== HELPERS =====================
function sha256File(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

function corruptEncryptedFile(encryptedPath) {
    const buffer = fs.readFileSync(encryptedPath);
    if (buffer.length === 0) return;
    const start = Math.max(16, 0);
    const pos = start + Math.floor(Math.random() * Math.max(1, buffer.length - start));
    buffer[pos] = buffer[pos] ^ 0xff;
    fs.writeFileSync(encryptedPath, buffer);
}

// ===================== SETUP =====================
app.use((req, res, next) => {
    res.setHeader('ngrok-skip-browser-warning', 'true');
    next();
});

const qrTemplatePath = path.join(__dirname, 'qr.html');
app.use(express.static(__dirname));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const MAX_FILE_SIZE = 50 * 1024 * 1024;

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = path.join(__dirname, 'uploads');
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage, limits: { fileSize: MAX_FILE_SIZE } });

const algorithm = 'aes-256-cbc';

const downloadCounts = {};

async function getNgrokURL() {
    try {
        const res = await axios.get('http://127.0.0.1:4040/api/tunnels');
        const tunnel = res.data.tunnels.find(t => t.proto === 'https');
        return tunnel ? tunnel.public_url : null;
    } catch {
        return null;
    }
}

// ===================== UPLOAD =====================
app.post('/upload', upload.single('file'), async (req, res) => {
    if (!req.body.password) return res.send("❌ Please provide a password.");

    const password = req.body.password;
    const maxDownloads = parseInt(req.body.maxDownloads) || 1;
    const accessMinutes = parseInt(req.body.accessMinutes) || 10;

    const inputPath = req.file.path;
    const encryptedFileName = req.file.filename + '.enc';
    const encryptedPath = path.join(__dirname, 'uploads', encryptedFileName);

    // SHA-256 of original file before encryption
    const originalSHA256 = await sha256File(inputPath);

    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(encryptedPath);

    output.write(iv);
    input.pipe(cipher).pipe(output);

    output.on('finish', async () => {
        fs.unlinkSync(inputPath);

        // SHA-256 of encrypted file
        const encryptedSHA256 = await sha256File(encryptedPath);

        const ngrokURL = await getNgrokURL();
        if (!ngrokURL) return res.send("❌ Ngrok not running");

        const validUntil = Date.now() + accessMinutes * 60 * 1000;
        const fileURL = `${ngrokURL}/download/${encryptedFileName}?validUntil=${validUntil}`;

        downloadCounts[encryptedFileName] = { count: 0, max: maxDownloads };

        // ✅ Record to blockchain
        const block = blockchain.addBlock({
            type: 'FILE_UPLOAD',
            filename: encryptedFileName,
            originalFilename: req.file.originalname,
            originalSHA256,
            encryptedSHA256,
            maxDownloads,
            accessMinutes,
            validUntil,
            uploadedAt: new Date().toISOString()
        });

        console.log(`🔗 Block #${block.index} mined | Hash: ${block.hash}`);
        console.log(`📦 Original SHA-256: ${originalSHA256}`);
        console.log(`🔒 Encrypted SHA-256: ${encryptedSHA256}`);

        const qrCode = await QRCode.toDataURL(fileURL);

        let html = fs.readFileSync(qrTemplatePath, 'utf-8');
        html = html.replace('__QR_IMAGE__', qrCode);
        html = html.replace(/__QR_LINK__/g, fileURL);
        html = html.replace('__ACCESS_SECONDS__', (accessMinutes * 60).toString());
        html = html.replace('__BLOCK_INDEX__', block.index);
        html = html.replace('__BLOCK_HASH__', block.hash);
        html = html.replace('__ORIGINAL_SHA256__', originalSHA256);
        html = html.replace('__CHAIN_VALID__', blockchain.isChainValid() ? '✅ Valid' : '❌ Tampered');

        res.send(html);
    });

    output.on('error', (err) => {
        console.error(err);
        res.status(500).send("❌ Encryption failed.");
    });
});

// ===================== FILE SIZE ERROR =====================
app.use((err, req, res, next) => {
    if (err.code === 'LIMIT_FILE_SIZE') return res.send("❗ File too large (Max: 50MB)");
    next(err);
});

// ===================== DOWNLOAD PAGE =====================
app.get('/download/:filename', (req, res) => {
    const validUntil = parseInt(req.query.validUntil);
    if (Date.now() > validUntil) return res.send("⏰ Link expired");

    const filename = req.params.filename;
    const block = blockchain.getBlockByFilename(filename);
    const blockInfo = block
        ? `<p style="font-size:12px;color:#888;">🔗 Block #${block.index} | SHA-256: <code style="word-break:break-all">${block.data.originalSHA256}</code></p>`
        : '';

    res.send(`
    <html>
    <head>
        <title>Password Required</title>
        <link rel="stylesheet" href="/style.css">
    </head>
    <body>
        <div class="container">
            <h2>🔐 Enter Password</h2>
            ${blockInfo}
            <form action="/decrypt/${filename}" method="POST">
                <input type="hidden" name="validUntil" value="${validUntil}" />
                <input type="password" name="password" placeholder="Enter password" required />
                <button type="submit">Decrypt & Download</button>
            </form>
        </div>
    </body>
    </html>
    `);
});

// ===================== DECRYPT =====================
app.post('/decrypt/:filename', async (req, res) => {
    const filename = req.params.filename;
    const password = req.body.password;
    const validUntil = parseInt(req.body.validUntil);

    if (Date.now() > validUntil) return res.send("⏰ Link expired");

    if (!downloadCounts[filename] || downloadCounts[filename].count >= downloadCounts[filename].max) {
        return res.send("❌ Download limit reached");
    }

    const encryptedPath = path.join(__dirname, 'uploads', filename);
    const decryptedPath = path.join(__dirname, 'uploads', 'dec-' + filename.replace('.enc', ''));

    // ✅ Verify encrypted file SHA-256 against blockchain record
    const block = blockchain.getBlockByFilename(filename);
    if (block) {
        const currentEncryptedSHA256 = await sha256File(encryptedPath);
        if (currentEncryptedSHA256 !== block.data.encryptedSHA256) {
            // Log tampering attempt to blockchain
            blockchain.addBlock({
                type: 'TAMPER_ALERT',
                filename,
                expectedHash: block.data.encryptedSHA256,
                foundHash: currentEncryptedSHA256,
                detectedAt: new Date().toISOString()
            });
            return res.send("🚨 SECURITY ALERT: File integrity check failed! The encrypted file has been tampered with.");
        }
    }

    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = Buffer.alloc(16);
    const fd = fs.openSync(encryptedPath, 'r');
    fs.readSync(fd, iv, 0, 16, 0);
    fs.closeSync(fd);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    const input = fs.createReadStream(encryptedPath, { start: 16 });
    const output = fs.createWriteStream(decryptedPath);

    input.pipe(decipher).pipe(output);

    output.on('finish', async () => {
        downloadCounts[filename].count++;

        // Log download event to blockchain
        blockchain.addBlock({
            type: 'FILE_DOWNLOAD',
            filename,
            downloadNumber: downloadCounts[filename].count,
            downloadedAt: new Date().toISOString()
        });

        res.download(decryptedPath, (err) => {
            if (!err) fs.unlink(decryptedPath, () => {});
        });
    });

    output.on('error', () => res.send("❌ Wrong password"));
});

// ===================== SIMULATE TAMPER =====================
app.get('/simulate-tamper', (req, res) => {
    const requestedFile = req.query.filename;
    const latestUpload = [...blockchain.chain].reverse().find(b => b.data && b.data.type === 'FILE_UPLOAD');
    const filename = requestedFile || (latestUpload ? latestUpload.data.filename : null);

    if (!filename) return res.send("❌ No uploaded encrypted file found. Upload a file first.");

    const encryptedPath = path.join(__dirname, 'uploads', filename);
    if (!fs.existsSync(encryptedPath)) {
        return res.send(`❌ Encrypted file not found: ${filename}`);
    }

    corruptEncryptedFile(encryptedPath);
    res.send(`✅ Tampered file: <strong>${filename}</strong><br><br><a href=\"/blockchain\">View Blockchain Explorer</a> | <a href=\"/download/${filename}?validUntil=${latestUpload ? latestUpload.data.validUntil : ''}\">Try Download</a>`);
});

// ===================== BLOCKCHAIN EXPLORER =====================
app.get('/blockchain', (req, res) => {
    const isValid = blockchain.isChainValid();
    const chain = blockchain.chain;

    const rows = chain.map(block => `
        <tr>
            <td>${block.index}</td>
            <td style="word-break:break-all;font-size:11px">${block.hash}</td>
            <td style="word-break:break-all;font-size:11px">${block.previousHash}</td>
            <td>${block.data.type || '-'}</td>
            <td>${block.data.filename || '-'}</td>
            <td style="font-size:11px;word-break:break-all">${block.data.originalSHA256 || block.data.foundHash || '-'}</td>
            <td>${block.timestamp}</td>
        </tr>
    `).join('');

    res.send(`
    <html>
    <head>
        <title>Blockchain Explorer</title>
        <link rel="stylesheet" href="/style.css">
        <style>
            body { padding: 20px; }
            table { width: 100%; border-collapse: collapse; font-size: 13px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background: #007bff; color: white; }
            tr:nth-child(even) { background: #f2f4f8; }
            .valid { color: green; font-weight: bold; }
            .invalid { color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🔗 Blockchain Explorer</h1>
        <p>Chain Integrity: <span class="${isValid ? 'valid' : 'invalid'}">${isValid ? '✅ All blocks valid' : '❌ Chain tampered!'}</span></p>
        <p>Total Blocks: <strong>${chain.length}</strong></p>
        <p><a href="/simulate-tamper">🔧 Simulate tamper on the latest uploaded file</a></p>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Block Hash (SHA-256)</th>
                    <th>Previous Hash</th>
                    <th>Event</th>
                    <th>Filename</th>
                    <th>File SHA-256</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
        <br>
        <a href="/">← Back to Upload</a>
    </body>
    </html>
    `);
});

// ===================== START SERVER =====================
const server = app.listen(port, () => {
    console.log(`✅ Server running at http://localhost:${port}`);
    console.log(`🔗 Blockchain Explorer: http://localhost:${port}/blockchain`);
    console.log(`🔗 Chain valid: ${blockchain.isChainValid()}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${port} is already in use. Use a different port or stop the process currently using it.`);
    } else {
        console.error(err);
    }
    process.exit(1);
});
