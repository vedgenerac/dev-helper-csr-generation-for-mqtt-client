const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const cors = require('cors');
const execAsync = promisify(exec);
const app = express();
const PORT = 3000;

app.use(cors({
    origin: 'http://localhost:8080',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
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
        const configPath = path.join(tempDir, 'openssl.cnf');

        try {
            // Generate ECC private key
            await execAsync(`openssl ecparam -name ${curve} -genkey -noout -out ${privateKeyPath}`);

            // Build subject string
            let subject = `/C=${country}/ST=${state}/L=${locality}/O=${organization}`;
            if (organizationalUnit) subject += `/OU=${organizationalUnit}`;
            subject += `/CN=${commonName}`;
            if (serialNumber) subject += `/serialNumber=${serialNumber}`;
            if (email) subject += `/emailAddress=${email}`;

            // Create OpenSSL config file with Key Usage extensions
            const opensslConfig = `
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
C  = ${country}
ST = ${state}
L  = ${locality}
O  = ${organization}
${organizationalUnit ? `OU = ${organizationalUnit}` : ''}
CN = ${commonName}
${serialNumber ? `serialNumber = ${serialNumber}` : ''}
${email ? `emailAddress = ${email}` : ''}

[ v3_req ]
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = clientAuth
`;

            fs.writeFileSync(configPath, opensslConfig);

            // Generate CSR with extensions
            await execAsync(
                `openssl req -new -key ${privateKeyPath} -out ${csrPath} -config ${configPath}`
            );

            // Read files
            const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
            const csr = fs.readFileSync(csrPath, 'utf8');

            // Extract public key
            const { stdout: publicKey } = await execAsync(
                `openssl ec -in ${privateKeyPath} -pubout 2>/dev/null`
            );

            // Verify CSR includes extensions
            const { stdout: csrText } = await execAsync(
                `openssl req -text -noout -in ${csrPath}`
            );

            // Cleanup
            fs.unlinkSync(privateKeyPath);
            fs.unlinkSync(csrPath);
            fs.unlinkSync(configPath);
            fs.rmdirSync(tempDir);

            res.json({
                success: true,
                privateKey,
                publicKey,
                csr,
                csrDetails: csrText // Include this so you can verify the extensions
            });

        } catch (error) {
            try {
                if (fs.existsSync(privateKeyPath)) fs.unlinkSync(privateKeyPath);
                if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
                if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
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
║ ECC CSR Generator Server (with mTLS extensions)                     ║
║ Running on http://localhost:${PORT}                                 ║
║ Open the below link on your web browser                             ║
║ http://localhost:${PORT}/index.html                                 ║
╚══════════════════════════════════════════════════════════════════════╝
  `);
});