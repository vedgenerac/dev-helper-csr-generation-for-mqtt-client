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

// Existing Client CSR Generation Endpoint
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
                csrDetails: csrText
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

// Broker CSR Generation Endpoint
app.post('/api/generate-broker-csr', async (req, res) => {
    try {
        const {
            curve = 'prime256v1',
            commonName,
            organization,
            organizationalUnit,
            country,
            state,
            locality,
            email,
            subjectAltNames = []
        } = req.body;

        if (!commonName) {
            return res.status(400).json({
                error: 'Common Name (CN) is required for broker certificate'
            });
        }

        const tempDir = path.join(__dirname, 'temp', `broker-${Date.now()}`);
        fs.mkdirSync(tempDir, { recursive: true });

        const privateKeyPath = path.join(tempDir, 'broker-private-key.pem');
        const csrPath = path.join(tempDir, 'broker-csr.pem');
        const configPath = path.join(tempDir, 'broker-openssl.cnf');

        try {
            // Generate ECC private key
            await execAsync(`openssl ecparam -name ${curve} -genkey -noout -out ${privateKeyPath}`);

            // Build Subject Alternative Names
            let sanSection = '';
            if (subjectAltNames && subjectAltNames.length > 0) {
                const sanEntries = subjectAltNames
                    .filter(san => san.value && san.value.trim())
                    .map((san, index) => `${san.type}.${index + 1} = ${san.value.trim()}`)
                    .join('\n');

                if (sanEntries) {
                    sanSection = `
[ alt_names ]
${sanEntries}`;
                }
            }

            // Create OpenSSL config file with broker-specific extensions
            const opensslConfig = `
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
${country ? `C  = ${country}` : ''}
${state ? `ST = ${state}` : ''}
${locality ? `L  = ${locality}` : ''}
${organization ? `O  = ${organization}` : ''}
${organizationalUnit ? `OU = ${organizationalUnit}` : ''}
CN = ${commonName}
${email ? `emailAddress = ${email}` : ''}

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
${subjectAltNames && subjectAltNames.length > 0 ? 'subjectAltName = @alt_names' : ''}
${sanSection}
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
                csrDetails: csrText,
                type: 'broker'
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
        console.error('Error generating broker CSR:', error);
        res.status(500).json({
            error: 'Failed to generate broker CSR',
            message: error.message
        });
    }
});

// NEW: Generate Root CA Certificate
app.post('/api/generate-root-ca', async (req, res) => {
    try {
        const {
            curve = 'prime256v1',
            commonName = 'MQTT Root CA',
            organization = 'MQTT Organization',
            organizationalUnit,
            country = 'US',
            state = 'California',
            locality = 'San Francisco',
            validityDays = 3650, // 10 years
            email
        } = req.body;

        const tempDir = path.join(__dirname, 'temp', `ca-${Date.now()}`);
        fs.mkdirSync(tempDir, { recursive: true });

        const caKeyPath = path.join(tempDir, 'ca-key.pem');
        const caCertPath = path.join(tempDir, 'ca-cert.pem');
        const configPath = path.join(tempDir, 'ca-openssl.cnf');

        try {
            // Generate ECC private key for CA
            await execAsync(`openssl ecparam -name ${curve} -genkey -noout -out ${caKeyPath}`);

            // Create OpenSSL config for CA
            const opensslConfig = `
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[ req_distinguished_name ]
C  = ${country}
ST = ${state}
L  = ${locality}
O  = ${organization}
${organizationalUnit ? `OU = ${organizationalUnit}` : ''}
CN = ${commonName}
${email ? `emailAddress = ${email}` : ''}

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
`;

            fs.writeFileSync(configPath, opensslConfig);

            // Generate self-signed CA certificate
            await execAsync(
                `openssl req -new -x509 -days ${validityDays} -key ${caKeyPath} -out ${caCertPath} -config ${configPath}`
            );

            // Read files
            const caKey = fs.readFileSync(caKeyPath, 'utf8');
            const caCert = fs.readFileSync(caCertPath, 'utf8');

            // Get CA certificate details
            const { stdout: certText } = await execAsync(
                `openssl x509 -in ${caCertPath} -text -noout`
            );

            // Cleanup
            fs.unlinkSync(caKeyPath);
            fs.unlinkSync(caCertPath);
            fs.unlinkSync(configPath);
            fs.rmdirSync(tempDir);

            res.json({
                success: true,
                caKey,
                caCert,
                certDetails: certText
            });

        } catch (error) {
            try {
                if (fs.existsSync(caKeyPath)) fs.unlinkSync(caKeyPath);
                if (fs.existsSync(caCertPath)) fs.unlinkSync(caCertPath);
                if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
                if (fs.existsSync(tempDir)) fs.rmdirSync(tempDir);
            } catch (e) { }
            throw error;
        }

    } catch (error) {
        console.error('Error generating Root CA:', error);
        res.status(500).json({
            error: 'Failed to generate Root CA',
            message: error.message
        });
    }
});

// NEW: Sign Client CSR with Root CA
app.post('/api/sign-client-cert', async (req, res) => {
    try {
        const {
            csr,
            caKey,
            caCert,
            validityDays = 365
        } = req.body;

        if (!csr || !caKey || !caCert) {
            return res.status(400).json({
                error: 'CSR, CA Key, and CA Certificate are required'
            });
        }

        const tempDir = path.join(__dirname, 'temp', `sign-client-${Date.now()}`);
        fs.mkdirSync(tempDir, { recursive: true });

        const csrPath = path.join(tempDir, 'client.csr');
        const caKeyPath = path.join(tempDir, 'ca-key.pem');
        const caCertPath = path.join(tempDir, 'ca-cert.pem');
        const certPath = path.join(tempDir, 'client-cert.pem');
        const configPath = path.join(tempDir, 'sign.cnf');

        try {
            // Write files
            fs.writeFileSync(csrPath, csr);
            fs.writeFileSync(caKeyPath, caKey);
            fs.writeFileSync(caCertPath, caCert);

            // Create signing config with client extensions
            const signingConfig = `
[ v3_client ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = clientAuth
`;

            fs.writeFileSync(configPath, signingConfig);

            // Create serial file path in temp directory
            const serialPath = path.join(tempDir, 'ca-cert.srl');

            // Sign the CSR
            await execAsync(
                `openssl x509 -req -in ${csrPath} -CA ${caCertPath} -CAkey ${caKeyPath} -CAcreateserial -CAserial ${serialPath} -out ${certPath} -days ${validityDays} -extfile ${configPath} -extensions v3_client`
            );

            // Read signed certificate
            const signedCert = fs.readFileSync(certPath, 'utf8');

            // Get certificate details
            const { stdout: certText } = await execAsync(
                `openssl x509 -in ${certPath} -text -noout`
            );

            // Cleanup
            fs.unlinkSync(csrPath);
            fs.unlinkSync(caKeyPath);
            fs.unlinkSync(caCertPath);
            fs.unlinkSync(certPath);
            fs.unlinkSync(configPath);
            if (fs.existsSync(serialPath)) {
                fs.unlinkSync(serialPath);
            }
            fs.rmdirSync(tempDir);

            res.json({
                success: true,
                signedCert,
                certDetails: certText
            });

        } catch (error) {
            try {
                if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
                if (fs.existsSync(caKeyPath)) fs.unlinkSync(caKeyPath);
                if (fs.existsSync(caCertPath)) fs.unlinkSync(caCertPath);
                if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
                if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
                if (fs.existsSync(tempDir)) fs.rmdirSync(tempDir);
            } catch (e) { }
            throw error;
        }

    } catch (error) {
        console.error('Error signing client certificate:', error);
        res.status(500).json({
            error: 'Failed to sign client certificate',
            message: error.message
        });
    }
});

// NEW: Sign Broker CSR with Root CA
app.post('/api/sign-broker-cert', async (req, res) => {
    try {
        const {
            csr,
            caKey,
            caCert,
            validityDays = 365,
            subjectAltNames = []
        } = req.body;

        if (!csr || !caKey || !caCert) {
            return res.status(400).json({
                error: 'CSR, CA Key, and CA Certificate are required'
            });
        }

        const tempDir = path.join(__dirname, 'temp', `sign-broker-${Date.now()}`);
        fs.mkdirSync(tempDir, { recursive: true });

        const csrPath = path.join(tempDir, 'broker.csr');
        const caKeyPath = path.join(tempDir, 'ca-key.pem');
        const caCertPath = path.join(tempDir, 'ca-cert.pem');
        const certPath = path.join(tempDir, 'broker-cert.pem');
        const configPath = path.join(tempDir, 'sign.cnf');

        try {
            // Write files
            fs.writeFileSync(csrPath, csr);
            fs.writeFileSync(caKeyPath, caKey);
            fs.writeFileSync(caCertPath, caCert);

            // Build Subject Alternative Names
            let sanSection = '';
            if (subjectAltNames && subjectAltNames.length > 0) {
                const sanEntries = subjectAltNames
                    .filter(san => san.value && san.value.trim())
                    .map((san, index) => `${san.type}.${index + 1} = ${san.value.trim()}`)
                    .join('\n');

                if (sanEntries) {
                    sanSection = `
[ alt_names ]
${sanEntries}`;
                }
            }

            // Create signing config with broker extensions
            const signingConfig = `
[ v3_broker ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
${subjectAltNames && subjectAltNames.length > 0 ? 'subjectAltName = @alt_names' : ''}
${sanSection}
`;

            fs.writeFileSync(configPath, signingConfig);

            // Create serial file path in temp directory
            const serialPath = path.join(tempDir, 'ca-cert.srl');

            // Sign the CSR
            await execAsync(
                `openssl x509 -req -in ${csrPath} -CA ${caCertPath} -CAkey ${caKeyPath} -CAcreateserial -CAserial ${serialPath} -out ${certPath} -days ${validityDays} -extfile ${configPath} -extensions v3_broker`
            );

            // Read signed certificate
            const signedCert = fs.readFileSync(certPath, 'utf8');

            // Get certificate details
            const { stdout: certText } = await execAsync(
                `openssl x509 -in ${certPath} -text -noout`
            );

            // Cleanup
            fs.unlinkSync(csrPath);
            fs.unlinkSync(caKeyPath);
            fs.unlinkSync(caCertPath);
            fs.unlinkSync(certPath);
            fs.unlinkSync(configPath);
            if (fs.existsSync(path.join(tempDir, 'ca-cert.srl'))) {
                fs.unlinkSync(path.join(tempDir, 'ca-cert.srl'));
            }
            fs.rmdirSync(tempDir);

            res.json({
                success: true,
                signedCert,
                certDetails: certText
            });

        } catch (error) {
            try {
                if (fs.existsSync(csrPath)) fs.unlinkSync(csrPath);
                if (fs.existsSync(caKeyPath)) fs.unlinkSync(caKeyPath);
                if (fs.existsSync(caCertPath)) fs.unlinkSync(caCertPath);
                if (fs.existsSync(certPath)) fs.unlinkSync(certPath);
                if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
                if (fs.existsSync(tempDir)) fs.rmdirSync(tempDir);
            } catch (e) { }
            throw error;
        }

    } catch (error) {
        console.error('Error signing broker certificate:', error);
        res.status(500).json({
            error: 'Failed to sign broker certificate',
            message: error.message
        });
    }
});

app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════════════╗
║ ECC CSR Generator Server (Client & Broker + CA)                     ║
║ Running on http://localhost:${PORT}                                 ║
║                                                                      ║
║ Endpoints:                                                           ║
║ • Client CSR:      POST /api/generate-csr                           ║
║ • Broker CSR:      POST /api/generate-broker-csr                    ║
║ • Root CA:         POST /api/generate-root-ca                       ║
║ • Sign Client:     POST /api/sign-client-cert                       ║
║ • Sign Broker:     POST /api/sign-broker-cert                       ║
║                                                                      ║
║ Web Interfaces:                                                      ║
║ • Home:   http://localhost:${PORT}/index.html                       ║
║ • Client: http://localhost:${PORT}/client.html                      ║
║ • Broker: http://localhost:${PORT}/broker.html                      ║
╚══════════════════════════════════════════════════════════════════════╝
  `);
});