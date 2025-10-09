const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const cors = require('cors'); // Add CORS package

const execAsync = promisify(exec);
const app = express();
const PORT = 3000;

// Enable CORS for specific origin or all origins
app.use(cors({
    origin: 'http://localhost:8080', // Allow requests from this origin (adjust if needed)
    methods: ['GET', 'POST', 'OPTIONS'], // Allow these HTTP methods
    allowedHeaders: ['Content-Type'], // Allow these headers
}));

app.use(express.json());
app.use(express.static('public'));

app.post('/api/generate-csr', async (req, res) => {
    try {
        const {
            curve = 'prime256v1',
            commonName,
            serialNumber,
            organization,
            organizationalUnit,
            country,
            state,
            locality,
            email
        } = req.body;

        if (!commonName || !organization || !country || !state || !locality) {
            return res.status(400).json({
                error: 'Missing required fields'
            });
        }

        const tempDir = path.join(__dirname, 'temp', Date.now().toString());
        fs.mkdirSync(tempDir, { recursive: true });
        const privateKeyPath = path.join(tempDir, 'private-key.pem');
        const csrPath = path.join(tempDir, 'csr.pem');

        try {
            // Generate ECC private key
            await execAsync(`openssl ecparam -name ${curve} -genkey -noout -out ${privateKeyPath}`);

            // Build subject string
            let subject = `/C=${country}/ST=${state}/L=${locality}/O=${organization}`;
            if (organizationalUnit) subject += `/OU=${organizationalUnit}`;
            subject += `/CN=${commonName}`;
            if (serialNumber) subject += `/serialNumber=${serialNumber}`;
            if (email) subject += `/emailAddress=${email}`;

            // Generate CSR
            await execAsync(
                `openssl req -new -key ${privateKeyPath} -out ${csrPath} -subj "${subject}"`
            );

            // Read files
            const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
            const csr = fs.readFileSync(csrPath, 'utf8');

            // Extract public key
            const { stdout: publicKey } = await execAsync(
                `openssl ec -in ${privateKeyPath} -pubout 2>/dev/null`
            );

            // Cleanup
            fs.unlinkSync(privateKeyPath);
            fs.unlinkSync(csrPath);
            fs.rmdirSync(tempDir);

            res.json({
                success: true,
                privateKey,
                publicKey,
                csr
            });
        } catch (error) {
            try {
                if (fs.existsSync(privateKeyPath)) fs.unlinkSync(privateKeyPath);
                if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
                if (fs.existsSync(tempDir)) fs.rmdirSync(tempDir);
            } catch (e) { }
            throw error;
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({
            error: 'Failed to generate CSR',
            message: error.message
        });
    }
});

app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║ ECC CSR Generator Server                                             ║
║ Running on http://localhost:${PORT}
  
   Open  the below link on your web browser   
║ http://localhost:${PORT}/index.html 
╚══════════════════════════════════════════════════════════════════════╝
  `);
});