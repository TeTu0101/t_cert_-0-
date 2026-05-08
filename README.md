------Club Certification Smart Contract------

#Description
This project is a smart contract built on the Stellar blockchain using Soroban SDK.
It was created to solve the problem of verifying real attendance at club events and automatically issuing tamper-proof certificates to eligible participants 
Which means replacing manual, paper-based processes with a transparent on-chain system.

#Features
-Event Management: Admin can create and manage events with configurable settings
-Attendee Registration: Members register for events with a face hash for identity verification
-QR-based Check-in: Secure one-time-use nonce system (15-second validity) to prevent replay attacks
-Presence Ping System: Periodic presence verification during events to ensure attendees stay throughout
-Face Verification: Face hash comparison at check-in to prevent impersonation
-Check-out Flow: Attendees must check out via QR nonce to finalize attendance
-Automatic Eligibility Check: Contract calculates attendance ratio (minimum 90%) before allowing certificate minting
-On-chain Certificate Minting: Eligible attendees receive a verifiable certificate stored on-chain
-Fraud Detection & Blacklist: Admin can report fraud, revoke certificates, and blacklist bad actors
-Read-only Queries: Anyone can query event data, attendance records, and certificates

#Contract
https://stellar.expert/explorer/testnet/tx/93ae88da6b555891cc61150bb7790a3662f12e69c9cdb13afaae4704647c29b7
https://stellar.expert/explorer/testnet/contract/CCIDOJBI5Z5SBKU7PDCNVTITCU3PTKDW4YXRMUMCHPTZLO3WQZWYKO3P?filter=history

    screenshots
    <img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/462c334d-4b58-4f29-aeb9-bcabe76418dd" />
    <img width="1600" height="900" alt="image" src="https://github.com/user-attachments/assets/1554b6af-18bc-4b3d-ab84-d6fee211866a" />

#Future scopes
-Integrate with a mobile frontend application for real-world usage (QR scanning, face capture, certificate display)
-Build a certificate verification portal where anyone can verify a participant's attendance record

#Profile
Khanh_Trinh
Skills: Rust, Soroban Smart Contract Development, Stellar Blockchain, Web3
