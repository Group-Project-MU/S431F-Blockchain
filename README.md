# S431F-Blockchain [Link](https://github.com/Group-Project-MU/S431F-Blockchain)
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

---

# 🔄 How the Program Works (Workflow)

Before using the app, both the doctor and patient must register separately. Then follow the phases below in order.

---

## Phase 1 – Registration (one-time setup)

**Doctor (do this first):**
1. Open the app and connect MetaMask
2. Select the **Doctor** role
3. Fill in the profile, directly click the **Get My Encryption Key** button and the key will automatically pasted to the public key field
4. Click **Register as Doctor** – this writes your profile to the blockchain
5. Set your **encryption public key** – patients use this to encrypt data for you

**Patient:**
1. Connect MetaMask and select the **Patient** role
2. Fill in personal details (name, ID, birthday, weight, height, etc.)
3. Enter the doctor's wallet address and the doctor's encryption public key
4. Click **Register as Patient** – your data is encrypted locally before going on-chain
5. Click **Show my encryption public key** to share your key to your authorized doctor in order to let them encrypted your data

---

## Phase 2 – Authorization and Coins (must be done before appointment)

These two steps can be done in either order, but both must be completed before the appointment can be settled.

**Patient authorizes the doctor:**
- Make sure you have fill in the doctor address in the profile before authorizing a doctor
- Go to Doctor Authorization
- Enter the doctor's wallet address, set to `true`
- Click **Apply authorization**
- Without this, the doctor cannot access any of your records

**Grant initial coins to the patient:**
- Go to Appointments & Coins
- Enter the patient address and an amount
- Click **Grant Initial Coins**
- Without coins, the final settlement will fail

---

## Phase 3 – Appointment

**Patient creates an appointment:**
1. Go to Appointments & Coins
2. Enter the doctor's address, date/time, fee, and reason
3. Click **Create appointment**
4. Status becomes: `Requested`

**Doctor responds:**
1. Click **Load appointment IDs** to see pending appointments
2. Enter the appointment ID
3. Click **Approve** or **Reject**
4. Status becomes: `Approved` or `Rejected`

---

## Phase 4 – Complete the Appointment (settlement + record in one step)

**Doctor does all of the following in one action:**
1. Enter the patient's wallet address and their encryption public key
2. Fill in Diagnosis, Prescription, and Notes
3. Click **Complete + Settle + Add Medical Record**

This single action does three things at once:
- Marks the appointment as `Completed`
- Transfers coins from the patient's balance to the doctor
- Encrypts the medical record and writes it to the blockchain

---

## Phase 5 – View Records

Either the patient or an authorized doctor can decrypt and view records:

1. Go to the **Clinical Explorer** section
2. Enter the patient's wallet address
3. Click **Decrypt profile**, **Decrypt records**, or **Decrypt allergies**
4. MetaMask will pop up asking you to confirm decryption
5. The plaintext data appears on screen

---

## Tips

If you have registered two different roles with the same wallet, you are suggested to enter the contract one by one to perform the action.<br>
Otherwise, the program will always identify you as a patient.<br>

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


