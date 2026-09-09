# PLIŌRA Threat Monitor — Production Deployment Guide

> 🚀 **Live Production Deployment:**
> - **Production URL:** [https://pliora-threat-monitor.vercel.app](https://pliora-threat-monitor.vercel.app)
> - **Deployment ID:** `dpl_4J8VRjmcfXTBgmPb2azHFMrrGwvb`
> - **Scope / Account:** `jarnil26s-projects`
> - **Status:** `READY` (HTTP 200 OK verified)
> - **Inspector URL:** [https://vercel.com/jarnil26s-projects/pliora-threat-monitor](https://vercel.com/jarnil26s-projects/pliora-threat-monitor)

---

## Target 1: Vercel (Recommended — Serverless Next.js 14)

Because PLIŌRA Threat Monitor is built on Next.js 14 (App Router), Vercel provides the fastest, zero-configuration global edge deployment.

### Method A: One-Command CLI Deployment

1. Open your terminal in `C:\PLIŌRA`.
2. Run the Vercel deployment command:
   ```bash
   npx vercel
   ```
   - If prompted to log in, press `Enter` to authenticate via your browser.
   - Set up and deploy `C:\PLIŌRA`? **`Y`**
   - Which scope do you want to deploy to? *(Select your account/team)*
   - Link to existing project? **`N`**
   - What's your project's name? **`pliora-threat-monitor`**
   - In which directory is your code located? **`./`**
   - Want to modify these settings? **`N`**
3. Deploy directly to production:
   ```bash
   npx vercel --prod
   ```

### Method B: Headless / CI Token Deployment

If you have a `VERCEL_TOKEN` (from [vercel.com/account/tokens](https://vercel.com/account/tokens)):

```powershell
$env:VERCEL_TOKEN = "your_vercel_token_here"
npx vercel --prod --yes
```

### Method C: GitHub Git Integration (Continuous Deployment)

1. Create a repository on GitHub (e.g. `github.com/your-username/pliora-threat-monitor`).
2. Push your committed code:
   ```bash
   git branch -M main
   git remote add origin https://github.com/your-username/pliora-threat-monitor.git
   git push -u origin main
   ```
3. Go to [vercel.com/new](https://vercel.com/new) and import the repository.
4. Add the **Environment Variables** (see below) in the Vercel Dashboard under **Settings → Environment Variables**.
5. Click **Deploy**. Vercel will automatically build and deploy every push to `main`.

---

## Required Environment Variables for Vercel

In your Vercel Project Dashboard (**Settings → Environment Variables**), configure:

| Variable Name | Value / Description | Required? |
|---|---|---|
| `NODE_ENV` | `production` | **Yes** |
| `MONGODB_URI` | `mongodb+srv://<user>:<password>@<cluster>.mongodb.net/pliora_prod` (MongoDB Atlas) | **Yes** (or set `ALLOW_IN_MEMORY_STORE=true` for demo) |
| `NEXTAUTH_SECRET` | 32+ character random string | **Yes** |
| `JWT_SECRET` | 32+ character random string | **Yes** |
| `ALLOW_IN_MEMORY_STORE` | `false` (Production guardrail requires live DB unless `true`) | **Yes** |
| `REDIS_URL` | Upstash Redis URL or serverless Redis connection string | Optional (in-memory queue fallback active) |
| `GEMINI_API_KEY` | Google Gemini API key for AI Security Analyst | Optional (falls back to offline template) |
| `STRIPE_SECRET_KEY` | Stripe live secret key (`sk_live_...`) | Optional (needed for real payments) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (`whsec_...`) | Optional (needed for billing sync) |

---

## Target 2: Docker & Docker Compose (VPS / AWS / Render / Railway)

If you prefer self-hosting with Docker (including containerized MongoDB and Redis):

1. **Start all services**:
   ```bash
   docker compose up -d --build
   ```
2. **Verify running containers**:
   ```bash
   docker ps
   ```
3. **Access your live instance**:
   Navigate to `http://localhost:3000` (or your server's public IP).

---

## Target 3: Production Server (`next start`)

To run the optimized production build directly on a Node.js server:

1. Ensure the production build is fresh:
   ```bash
   npm run build
   ```
2. Start the production listener:
   ```bash
   npm run start
   ```
   The application will serve on port `3000`.
