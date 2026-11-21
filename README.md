# Sentinel AI

Sentinel AI is a source-backed cybersecurity intelligence platform. It imports official
vulnerability records and displays provenance, synchronization health, and calculated
dashboard metrics. It does not fabricate vulnerabilities or present predictions as facts.

## Run

```powershell
npm install
copy .env.example .env
npm run sync
npm start
```

Open `http://localhost:3000`.

Set `NVD_API_KEY` to use an approved NVD API key. Public unauthenticated requests are
rate-limited. Other provider configuration is documented in `.env.example`.
