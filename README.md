# S431F-Blockchain
# 🏥 Medical Chain – Encrypted Healthcare DApp

A blockchain-based healthcare system that enables secure storage and sharing of patient data using end-to-end encryption.

This system allows patients and doctors to interact through smart contracts, ensuring:
- Privacy (encrypted medical data)
- Trust (on-chain verification)
- Controlled access (doctor authorization)

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


