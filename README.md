# CUPPEE on GitHub Pages

Static demo of the CoHee **CUPPEE** membership desk.

GitHub Pages cannot run Python/Flask or talk to a PC/SC NFC reader, so this build uses:

- **Simulated NFC** (random customers on Scan)
- **AES-128** via Web Crypto
- **Encrypted membership records** in `localStorage` (browser-only)

## Enable Pages

1. Push this repo to GitHub  
2. **Settings → Pages → Build and deployment**  
   - Source: **GitHub Actions**  
3. Push to `main`/`master` (or run the **Deploy GitHub Pages** workflow)  

Site URL will look like:  
`https://<user>.github.io/<repo>/`

Or set Pages to **Deploy from a branch** → folder **`/docs`**.

## Demo password

Admin / Data Base: `cohee2026`

## Local hardware NFC

Use the Flask app in `webapp/` on a shop PC with the RF-IC02 reader.
