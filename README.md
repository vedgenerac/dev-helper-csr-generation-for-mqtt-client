# ECC CSR Generator
A web-based tool to generate ECC (Elliptic Curve Cryptography) Certificate Signing Requests (CSRs) using OpenSSL.
## Prerequisites

Node.js (version 14.x or higher recommended)
npm (comes with Node.js)
OpenSSL (installed on your system for CSR generation)

## Installation

### 1. Clone the Repository:

If you have a Git repository, clone it:git clone <repository-url>


Otherwise, download the files (server.js, index.html, etc.) and place them in a project directory.


###  2. Navigate to the Project Directory:

Open a terminal and change to the project directory:cd <project-directory>




###  3. Install Dependencies:

Run the following command to install the required Node.js packages:`npm install`




###  4. Set Up Project Structure:

Create a public/ directory in the project root if it doesn’t exist.
Move index.html into the public/ directory.



## Running the Application

### 1. Start the Server:

In the terminal, run the server script:node server.js


You should see a message indicating the server is running:╔════════════════════════════════════════════════╗
║ ECC CSR Generator Server                        ║
║ Running on http://localhost:3000                ║
╚════════════════════════════════════════════════╝




### 2. Access the Application:

Open your web browser and navigate to:http://localhost:3000/index.html


The ECC CSR Generator interface should load, allowing you to input details and generate a CSR.



## Usage

### 1. Fill Out the Form:

Enter the required fields: Common Name (CN), Organization (O), Country (C), State/Province (ST), and City/Locality (L).
Optionally, provide a Serial Number, Organizational Unit (OU), and Email Address.
The Common Name (CN) field defaults to "Enter userId" for easy copy-paste; replace it with a valid user ID (e.g., a UUID like 71baf012-534c-45ee-a1a5-4067037e9caa).


### 2. Generate the CSR:

Click the "Generate CSR" button to create the Certificate Signing Request, Private Key, and Public Key.
The results will be displayed, and you can copy or download them.


### 3. Security Note:

Keep the generated Private Key secure and never share it or commit it to version control.



## Troubleshooting

### CORS Issues: 
    Ensure index.html is served via http://localhost:3000/index.html. If using a different port (e.g., http://localhost:8080), update the cors configuration in server.js to match the origin.
### OpenSSL Errors: 
    Verify OpenSSL is installed and accessible from the command line (e.g., run openssl version).
### Server Not Running: 
    Check the terminal for errors and ensure the port (3000) is not in use by another process.

## Dependencies

`express`: Web framework for Node.js
`cors`: Middleware for handling CORS

Install these via `npm install express cors` as described above.