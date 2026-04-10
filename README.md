# S431F-Blockchain
# 🏥 Medical Chain – Encrypted Healthcare DApp

A blockchain-based healthcare system that enables secure storage and sharing of patient data using end-to-end encryption.

This system allows patients and doctors to interact through smart contracts, ensuring:
- Privacy (encrypted medical data)
- Trust (on-chain verification)
- Controlled access (doctor authorization)
### [Quick Demo](https://drive.google.com/file/d/1js7yYK3cFe0IUICcffBCxM95tYAKpOWG/view?usp=drive_link)
---

# 🚀 Features

## 🔌 Wallet & App Flow
- Connect MetaMask wallet
- Auto-detect contracts from pasted addresses
- Choose Patient or Doctor workspace after connecting
- Show current network and account status

## 👤 Patient
- Register encrypted personal profile
- Update profile securely
- Show own encryption public key (for secure sharing)
- Authorize / revoke doctor access
- Discover registered doctors and auto-fill doctor address
- Create appointments with doctors
- Load my appointment IDs
- View appointment details by appointment ID
- Cancel appointment
- View medical records (decrypted locally)
- View allergy records
- Check my token balance (coins)

## 👨‍⚕️ Doctor
- Register doctor profile
- Update doctor profile
- Load doctor profile from DoctorRegistry
- Show own encryption public key
- View authorized patients
- Load doctor appointment IDs
- Approve / reject appointments
- Add medical records (encrypted)
- Add allergy records (encrypted)
- Complete appointment + settlement + add medical record
- Grant initial patient coins via DoctorRegistry

## 🔐 Security
- End-to-end encryption using MetaMask public key
- Data stored on-chain is encrypted
- Only authorized parties can decrypt (Only patient can authorize/unauthorize doctor)

## 🔑 Hybrid Authentication
- **Wallet authentication (Web3 identity):** users authenticate with MetaMask by connecting their wallet and signing transactions.
- **Role-based contract checks:** smart contracts enforce patient/doctor permissions and on-chain authorization rules.
- **Data-level access control:** even with on-chain read access, medical payloads remain encrypted and require the correct wallet key to decrypt.
- **Encryption technique:** used MetaMask-compatible public-key encryption with `x25519-xsalsa20-poly1305` (NaCl box pattern with ephemeral key + nonce) for profile, medical record, and allergy payload protection.
- **End-to-end decryption path:** payloads are encrypted in the frontend and decrypted by wallet-assisted methods, so plaintext is not stored on-chain.
- **Two-layer trust model:** blockchain validates identity and permissions, while encryption protects confidentiality of profile, record, and allergy data.
- 
---

# 🧱 System Architecture

## Smart Contracts
- `PatientRegistry`
- `DoctorRegistry`

## Frontend
- HTML + CSS dashboard
- `app.js` handles:
  - MetaMask interaction
  - Encryption / decryption
  - Contract calls

## Encryption Stack
- MetaMask `eth_getEncryptionPublicKey`
- `eth-sig-util`
- `tweetnacl`

---

# 📦 Installation

```bash
git clone <your-repo>
cd <project>
rm -rf node_modules
npm install
```

Then follow this workflow:

1. Start Ganache.
2. Deploy contracts:
   ```bash
   truffle migrate
   ```
3. Verify network and deployment:
   ```bash
   truffle networks
   ```
4. Run the frontend:
   ```bash
   npm run dev
   ```


