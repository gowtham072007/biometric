# Geo-Fenced Biometric Mobile Web Application

Production-ready, mobile-first web application for location-restricted biometric authentication (attendance) built with **Python Flask**, **WebAuthn / Passkeys**, **SQLite / PostgreSQL**, and **GPS Geofencing (Haversine Formula)**.

---

## 1. Project Overview

This application provides secure physical attendance verification for colleges, corporate offices, or organization sites. Users can authenticate using their smartphone's native biometric hardware (Fingerprint, Face ID, or Device PIN), but authentication is strictly permitted **only when the user is physically inside an administrator-configured geographic radius** around an authorized location center.

### Key Highlights
* **Strict 1-User-Per-Device Policy**: Anti-proxy attendance mechanism ensuring each physical hardware device is exclusively bound to a single user account, preventing buddy punching or account sharing on one phone.
* **Zero Raw Biometric Storage**: Fingerprint and Face ID data never leave the user's device. Public-key cryptography (WebAuthn / FIDO2) handles authentication via operating system prompts.
* **Server-Enforced Geofencing**: Physical distance to the target location center is independently calculated on the server using the Haversine formula. Frontend Boolean flags are never trusted.
* **Mobile-First PWA Support**: Responsive dark-mode card layout with bottom navigation, installable PWA manifest, offline app shell caching via Service Worker, and touch-optimized biometric triggers.
* **Full Administrative Controls**: Admin dashboard with attendance analytics, user activation/deactivation, device unbind/reset controls, interactive Leaflet map coordinate picker, date/status log filters, and one-click CSV report exports.

---

## 2. Technology Stack

* **Frontend**: HTML5, CSS3 (Vanilla CSS variables, glassmorphism, dark/light theme tokens), Vanilla JavaScript (ES6+), WebAuthn API (`navigator.credentials`), Geolocation API, Leaflet.js (OpenStreetMap), PWA Service Worker.
* **Backend**: Python 3.13, Flask, `flask-cors`, `pywebauthn` (WebAuthn / Passkey FIDO2 standard), `werkzeug.security`.
* **Database**: SQLite (Development) with abstracted SQL connection layer compatible with PostgreSQL / MySQL.
* **Testing**: Pytest automated test suite.

---

## 3. Project Structure

```
d:\bio\
├── backend/
│   ├── app.py                      # Flask app factory, static routes, blueprint registration & seed
│   ├── config.py                   # Environment configuration loader
│   ├── database.py                 # SQLite database initialization & transaction management
│   ├── models/
│   │   └── schemas.py              # User, WebAuthnCredential, GeofenceSettings, AuthLog queries
│   ├── routes/
│   │   ├── auth_routes.py          # Session auth, registration, login, profile, logout endpoints
│   │   ├── webauthn_routes.py      # WebAuthn options & assertion verification endpoints
│   │   ├── geofence_routes.py      # Geofence location settings & pre-flight verification endpoints
│   │   └── admin_routes.py         # Admin dashboard, user status toggle, geofence config & CSV export
│   ├── services/
│   │   ├── geofence.py             # Server-side Haversine distance, coordinate & accuracy validation
│   │   └── webauthn_service.py     # WebAuthn registration & assertion verification service (pywebauthn)
│   └── utils/
│       ├── security.py             # Password hashing & role-based authentication decorators
│       └── serializers.py          # Base64URL encoding/decoding & SQLite row convertors
├── frontend/
│   ├── index.html                  # Landing page & navigation launcher
│   ├── login.html                  # Password & Passkey shortcut login screen
│   ├── register.html               # User registration & passkey enrollment page
│   ├── dashboard.html              # Mobile user dashboard
│   ├── authenticate.html           # Location verification & biometric authentication screen
│   ├── history.html                # User attendance history log
│   ├── admin.html                  # Admin dashboard & overview statistics
│   ├── users.html                  # Admin user management panel
│   ├── location.html               # Admin location settings with interactive Leaflet map
│   ├── logs.html                   # Admin audit logs with date filters & CSV export
│   ├── privacy.html                # Privacy policy notice
│   ├── css/
│   │   ├── main.css                # Primary design system, typography, dark mode, responsive layout
│   │   └── components.css          # Badges, spinners, maps, modals, touch targets
│   └── js/
│       ├── app.js                  # Global application router, toast alerts, session checking
│       ├── api.js                  # REST API fetch wrapper with credentials
│       ├── geo.js                  # Geolocation API wrapper & client Haversine distance calculator
│       ├── webauthn.js             # WebAuthn JS helper (base64url ArrayBuffers, navigator.credentials)
│       └── admin.js                # Admin map controller & dashboard handlers
├── static/
│   ├── manifest.json               # PWA Web App Manifest
│   ├── service-worker.js           # PWA Service Worker script
│   └── icons/
│       ├── icon-192.png            # 192x192 PNG PWA App Icon
│       └── icon-512.png            # 512x512 PNG PWA App Icon
├── tests/
│   ├── test_geofence.py            # Haversine distance, coordinate, accuracy & demo mode unit tests
│   ├── test_webauthn.py            # WebAuthn registration & authentication option unit tests
│   └── test_auth_api.py            # API integration tests for auth, login, and admin authorization
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment template file
└── README.md                       # Comprehensive guide and documentation
```

---

## 4. Installation & Quick Start

### Step 1 — Prerequisites
Ensure Python 3.10+ is installed on your system.

### Step 2 — Environment & Dependency Setup
Open terminal in the project root:

```bash
# Create Python virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Activate virtual environment (Linux / macOS)
# source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### Step 3 — Environment Variables
Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

---

## 5. Running the Application

Start the Flask development server:

```bash
python -m backend.app
```

The server will initialize the SQLite database (`database/geofence_bio.db`), seed the initial Admin user, and listen at:
`http://localhost:5000` (or `http://127.0.0.1:5000`).

---

## 6. Accessing Default Accounts & Initial Setup

### Default System Administrator
* **User ID / Login**: `admin`
* **Password**: `Admin@123456`
* **Admin Dashboard**: `http://localhost:5000/admin.html`

### Configuring Authorized Location (Geofence Center)
1. Log in as `admin`.
2. Go to **Admin → Location Settings** (`http://localhost:5000/location.html`).
3. Click on the interactive Leaflet map to set your target location center (e.g. your campus or office building), or click **Use Current Admin Device GPS Location**.
4. Select or input the permitted radius (e.g., `100` meters).
5. Click **Save Location Settings**.

> [!TIP]
> **Demo / Testing Mode**: If you are testing the app from outside your configured physical geofence, enable the **"Enable Demo / Testing Mode"** checkbox on `location.html`. This allows WebAuthn biometric enrollment and verification to succeed while displaying distance metrics.

---

## 7. Testing Biometric Authentication (User Flow)

1. Open `http://localhost:5000/register.html` on your mobile device or browser.
2. Register a new user account (e.g. `user_id: student01`, `full_name: Alex Rivera`).
3. Click **REGISTER BIOMETRIC PASSKEY** to enroll your smartphone's Fingerprint / Face ID.
4. Navigate to **Authenticate** (`http://localhost:5000/authenticate.html`).
5. Grant browser Location permission when prompted.
6. The app calculates distance to the authorized center:
   * **If Inside Radius**: The large touch target button glows green and enables **"AUTHENTICATE WITH BIOMETRIC"**.
   * **If Outside Radius**: The button is disabled with a clear message: *"You are outside the permitted area."*
7. Tap the biometric button to invoke your device's fingerprint or Face ID prompt.
8. Upon successful scan, the server verifies the WebAuthn signature and records your attendance event in the database.

---

## 8. Executing Automated Test Suite

Run the full pytest suite:

```bash
pytest tests/
```

All 11 unit and integration tests verify:
* Haversine distance calculations & boundary cases.
* Coordinate range validation & GPS accuracy filtering.
* WebAuthn option generation & challenge verification.
* Role-based REST API authorization (User vs. Admin).

---

## 9. Security & Privacy Considerations

* **WebAuthn Origin Enforcement**: WebAuthn options and assertion verifications check `WEBAUTHN_RP_ID` (`localhost`) and `WEBAUTHN_ORIGIN` (`http://localhost:5000`) to prevent phishing and relay attacks.
* **Server-Side Authorization**: The server independently verifies latitude, longitude, GPS accuracy, and distance for every biometric request. Client-side Boolean flags are ignored.
* **Data Privacy**: No raw fingerprint or facial imagery is collected, stored, or processed. Biometric data remains strictly inside the user's device enclave.

---

## 10. Deploying to Vercel

The application is fully configured for deployment on **Vercel** serverless infrastructure using `@vercel/python`.

### Step 1 — Import to Vercel
1. Push your code to GitHub / GitLab / Bitbucket.
2. In the [Vercel Dashboard](https://vercel.com/dashboard), click **"Add New..."** → **"Project"** and import your repository.
3. Vercel automatically detects `vercel.json` and `api/index.py`.

### Step 2 — Configure Environment Variables in Vercel
In **Project Settings → Environment Variables**, configure the following:

| Variable | Recommended Production Value | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://postgres.[ref]:[pw]@aws-0-[region].pooler.supabase.com:6543/postgres` | Supabase / PostgreSQL connection pooler (IPv4 compatible) |
| `SECRET_KEY` | *(Generate a 64+ char random string)* | Flask session secret key |
| `SESSION_COOKIE_SECURE` | `True` | Enforces HTTPS-only session cookies |
| `WEBAUTHN_RP_ID` | `your-project.vercel.app` *(or your custom domain)* | Relying Party domain for WebAuthn passkeys |
| `WEBAUTHN_ORIGIN` | `https://your-project.vercel.app` *(or https://yourdomain.com)* | Full HTTPS origin for WebAuthn authentication |
| `ADMIN_PASSWORD` | *(Your secure admin password)* | Initial default administrator password |
| `ADMIN_EMAIL` | `admin@yourdomain.com` | Initial default administrator email |

> [!NOTE]
> If `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` are not explicitly provided in environment variables, the system will automatically auto-detect your active Vercel production domain from `VERCEL_PROJECT_PRODUCTION_URL` or `VERCEL_URL`.

### Step 3 — Deploy via Vercel CLI (Alternative)
You can also deploy directly from your terminal using the Vercel CLI:

```bash
# Install Vercel CLI (if not already installed)
npm install -g vercel

# Log in and deploy preview
vercel

# Deploy directly to production
vercel --prod
```

---

## 11. License

Developed for Secure Geo-Fenced Biometric Attendance & Authentication.

