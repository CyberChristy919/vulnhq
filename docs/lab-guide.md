# VulnHQ Setup Lab Guide

A step-by-step lab for people who know vulnerability management but have never set up an app. No coding is needed. Copy each command, paste it, press Enter and compare what you see with the checkpoint.

| | |
|---|---|
| **Time** | 60 to 90 minutes the first time (most of it is waiting for downloads) |
| **You need** | A Windows 10 or 11 PC, admin rights, internet access |
| **Memory** | 16 GB RAM recommended for the optional local AI. 8 GB works with a smaller model (Lab 6). |
| **Data** | A fictional lab inventory of 10 servers. No real company data is used. |

## What you will build

By the end you will have VulnHQ running on your own computer:

- A **fix list** that ranks vulnerabilities by real exploitation evidence (CISA KEV, EPSS) and business impact
- An **Assets** page that shows which servers are exposed and which have stale scans
- An **Ask** page that answers ten common leadership questions from the data, with an optional local AI that never sends data off your machine

Then you will review how it scores risk and tell us what an expert would change.

## Words you will see

| Word | Plain-English meaning |
|---|---|
| **Terminal / PowerShell** | A window where you type commands instead of clicking. Every command in this guide goes here. |
| **Repo (repository)** | The project folder, stored on GitHub. "Cloning" downloads a copy. |
| **Virtual environment (venv)** | A private box of Python add-ons for this project so it does not affect anything else on your PC. |
| **Database** | Where the app stores assets, software and findings. VulnHQ uses PostgreSQL. |
| **Backend** | The engine. It reads the database, does the scoring and answers questions. |
| **Frontend** | The screens you click in your web browser. |
| **Port** | A numbered door on your computer. The backend uses 8000, the frontend uses 5173, the database uses 5432. |
| **API** | The way the frontend asks the backend for data. You can see it at `http://127.0.0.1:8000/docs`. |

## How to open PowerShell

1. Press the **Windows** key, type `PowerShell`.
2. For most labs, click **Windows PowerShell**.
3. When a step says **admin PowerShell**, right-click it and choose **Run as administrator**.

Tips:

- Paste with **right-click** or **Ctrl+V**.
- A command is done when you see the prompt again (for example `PS C:\Users\you>`).
- Red text means an error. Check the Troubleshooting section at the end.
- Every lab starts with a full `cd` command, so it does not matter which folder PowerShell opens in.

---

## Lab 0: Install the tools

Open an **admin PowerShell** and run these one at a time. Accept any prompts.

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.12 -e
winget install --id OpenJS.NodeJS.LTS -e
```

### Install PostgreSQL 16

1. Go to the [PostgreSQL Windows installer page](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads) and download **version 16** for Windows x86-64.
2. Run the installer and keep the defaults, with these notes:
   - When asked for a **password for the postgres user**, choose one and **write it down**. You need it in Lab 3.
   - Keep the port as **5432**.
   - At the end, you can uncheck **Stack Builder**. It is not needed.

### Checkpoint

**Close every PowerShell window and open a new normal one** (new installs are only seen by new windows). Then run:

```powershell
git --version
python --version
node --version
npm --version
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" --version
```

You should see five version numbers, such as `git version 2.x`, `Python 3.12.x`, `v22.x`, `10.x` and `psql (PostgreSQL) 16.x`.

---

## Lab 1: Download the project

```powershell
cd $HOME\Documents
git clone https://github.com/CyberChristy919/vulnhq.git
cd $HOME\Documents\vulnhq
dir
```

### Checkpoint

You should see folders named `backend`, `frontend`, `docs` and `sample-data`.

---

## Lab 2: Create the database

```powershell
& "C:\Program Files\PostgreSQL\16\bin\psql.exe" -U postgres -c "CREATE DATABASE vulnapp;"
```

Type the postgres password from Lab 0 when asked. Nothing appears while you type. That is normal.

### Checkpoint

You should see `CREATE DATABASE`. If it says the database already exists, that is fine too.

---

## Lab 3: Set up the backend

### Step 1: Create the virtual environment and install add-ons

```powershell
cd $HOME\Documents\vulnhq\backend
python -m venv .venv
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

- If asked about the execution policy, type `Y` and press Enter. This lets PowerShell run the project's activation script.
- After activation, your prompt starts with `(.venv)`. **Every backend command in this guide needs that `(.venv)`**. If you open a new window, run the `cd` and `Activate.ps1` lines again.
- The install takes a few minutes.

### Step 2: Tell the app where the database is

```powershell
notepad .env
```

Click **Yes** to create the file, paste these two lines, replace `YOUR_PASSWORD` with your postgres password, then save and close Notepad:

```text
DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/vulnapp
NVD_API_KEY=
```

Notes:

- If your password contains `@`, `:`, `/`, `#` or `%`, replace them with `%40`, `%3A`, `%2F`, `%23` and `%25`. For example, `Pa@ss` becomes `Pa%40ss`.
- Leave `NVD_API_KEY` blank. The lab data does not need it.
- Only put these two settings in `.env`. Other settings in this file stop the app from starting.
- **Never commit or share `.env`.** It holds your password. The project already tells Git to ignore it.

### Checkpoint

```powershell
dir .env
```

You should see one file named `.env`. If Notepad saved it as `.env.txt`, rename it with `Rename-Item .env.txt .env`.

---

## Lab 4: Load the lab data

Still in the backend window with `(.venv)` showing:

```powershell
cd $HOME\Documents\vulnhq\backend
python -m scripts.migrate_db
python -m scripts.load_kev
python -m scripts.import_inventory ..\sample-data\lab-inventory.json --context ..\sample-data\lab-context.json
python -m scripts.load_epss
```

What each one does:

| Command | What it does |
|---|---|
| `migrate_db` | Builds the database tables |
| `load_kev` | Downloads the CISA Known Exploited Vulnerabilities catalog (about 1,700+ entries) |
| `import_inventory` | Loads the 10 fictional servers, their software and business context, then matches software to CVEs |
| `load_epss` | Downloads the probability of exploitation for each CVE. This one takes a few minutes. |

### Checkpoint

The import should end with a summary close to this:

```text
Assets:    10 created, 0 updated
Software:  17 items checked
Findings:  33 created on 10 assets
           23 known exploited (KEV), 7 need a configuration check
```

It ends with a note about 6 context updates and a reminder to run `load_epss`, which is the next command.

KEV numbers can grow slightly over time as CISA adds entries.

---

## Lab 5: Start the app

The app needs **three things running**: the database, the backend and the frontend.

### Step 1: Make sure the database is running

In an **admin PowerShell**:

```powershell
Get-Service postgresql* | Start-Service
Get-Service postgresql*
```

Status should say `Running`.

### Step 2: Start the backend (window 1)

```powershell
cd $HOME\Documents\vulnhq\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

Leave this window open. You should see `Uvicorn running on http://127.0.0.1:8000`.

### Step 3: Start the frontend (window 2)

Open a **second** PowerShell window:

```powershell
cd $HOME\Documents\vulnhq\frontend
npm install
npm run dev
```

`npm install` is only needed the first time. Leave this window open. You should see `Local: http://localhost:5173/`.

### Checkpoint

1. Open your browser to **http://localhost:5173**. You should see the VulnHQ dashboard with **10 assets**, **33 open findings** and **2 stale scans**.
2. Optional: open **http://127.0.0.1:8000/docs** to see the API, the menu the frontend uses to ask for data.

---

## Lab 6 (optional): Turn on the local AI

Without this, the Ask page still works with keywords and the shortcut buttons. With it, the app understands questions worded in your own way. The AI only picks which question you asked. The numbers always come from the database.

In a normal PowerShell window:

```powershell
irm https://ollama.com/install.ps1 | iex
```

Close and reopen PowerShell, then download the model:

| Your RAM | Command |
|---|---|
| 16 GB or more | `ollama pull granite4.2:8b` |
| 8 GB | `ollama pull granite4.2:3b` |

**If you used the 3b model**, start the backend this way instead of the Lab 5 command:

```powershell
cd $HOME\Documents\vulnhq\backend
.\.venv\Scripts\Activate.ps1
$env:OLLAMA_MODEL = "granite4.2:3b"
uvicorn app.main:app --reload
```

### Checkpoint

```powershell
ollama list
```

You should see the granite model. The first AI question can take 20 to 60 seconds while the model loads. After that it is faster.

---

## Lab 7: Guided tour and expert review

This is where your industry knowledge matters. Work through each exercise and jot down anything that looks wrong, confusing or missing.

### Exercise 1: The fix list

1. Open the **Fix list**.
2. Find the top item. Click it to see the **score breakdown**.
3. Ask yourself: would your team fix this one first? Why or why not?

### Exercise 2: Assets and stale scans

1. Open **Assets**.
2. Find the two servers flagged for **stale scans** (no scan in over 90 days).
3. Ask yourself: is 90 days the right threshold for your industry?

### Exercise 3: Ask the shortcut questions

1. Open **Ask** and click each of the ten shortcut buttons.
2. With the lab data, you should see answers such as:
   - "Which business unit has the most critical exposure?" → **Finance**
   - "Which software package should we patch first...?" → **Fortinet FortiOS**
   - "What would patching Apache HTTP Server... reduce?" → **33 to 30 findings**
3. Click a finding to check that the CVE, source and due date make sense.

### Exercise 4: Ask in your own words

Type questions the way an executive or auditor would ask them, for example:

- "Who is most exposed, by department?"
- "What's the one thing we should patch this week?"
- "Anything overdue on the CISA list?"

Note which questions it answers well and which it does not understand. Questions it misses are the most useful feedback.

### Exercise 5: The "Apache" ambiguity test

Ask "What would patching Apache reduce?" "Apache" can mean several products. Check whether the app asks you to clarify instead of guessing.

### Exercise 6: Add software

Add a product to a server and watch the findings change. Open **Assets**, click a server and use its **Add software** form, or run this in the backend window (stop the server with **Ctrl+C** first, or use a third window with `(.venv)` active):

```powershell
cd $HOME\Documents\vulnhq\backend
python -m scripts.add_software lab-hr-app01.example.local "Atlassian Confluence" 8.5.1
```

This product is not in the vetted rules, so the app looks it up in the National Vulnerability Database (NVD). That can take a minute without an API key. Refresh the browser. The HR server should now show new Confluence findings.

### Expert review checklist

| Area | Where to look | Question to answer |
|---|---|---|
| Scoring weights | [docs/scoring.md](scoring.md) | Are the weights for KEV, EPSS, CVSS, internet exposure and money movement right? |
| Vetted product rules | `backend/data/vuln_rules.json` | Are any affected version ranges wrong or missing? |
| Question wording | The Ask page | Are these the questions leadership actually asks? What is missing? |
| Deadlines | Fix list and Ask | Do the due dates match how your organization tracks SLAs? |

### How to send feedback

- Open an issue at [github.com/CyberChristy919/vulnhq/issues](https://github.com/CyberChristy919/vulnhq/issues). Include the page, what you expected and what you saw. A screenshot helps.
- **Found a security problem in the app itself?** Do not open a public issue. Use the repo's **Security** tab and choose **Report a vulnerability** so it stays private.

---

## Lab 8 (optional): Run the automated tests

```powershell
cd $HOME\Documents\vulnhq\backend
.\.venv\Scripts\Activate.ps1
pytest
```

### Checkpoint

The last line should say all tests **passed** (173 at the time of writing). These tests check the scoring, matching and question answers automatically.

---

## Daily cheat sheet

**Start**

1. Admin PowerShell: `Get-Service postgresql* | Start-Service`
2. Window 1:
   ```powershell
   cd $HOME\Documents\vulnhq\backend
   .\.venv\Scripts\Activate.ps1
   uvicorn app.main:app --reload
   ```
3. Window 2:
   ```powershell
   cd $HOME\Documents\vulnhq\frontend
   npm run dev
   ```
4. Browser: http://localhost:5173

**Stop**: press **Ctrl+C** in windows 1 and 2.

**Get the latest version**

```powershell
cd $HOME\Documents\vulnhq
git pull
cd $HOME\Documents\vulnhq\backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m scripts.migrate_db
```

**Start over with clean lab data**

```powershell
cd $HOME\Documents\vulnhq\backend
.\.venv\Scripts\Activate.ps1
python -m scripts.reset_demo
python -m scripts.import_inventory ..\sample-data\lab-inventory.json --context ..\sample-data\lab-context.json
```

Type `RESET` when asked. This deletes assets and findings, then the import loads the lab servers again.

---

## Troubleshooting

| What you see | Fix |
|---|---|
| `Activate.ps1 cannot be loaded because running scripts is disabled` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, type `Y`, then try again. |
| `python is not recognized` or the Microsoft Store opens | Close and reopen PowerShell. If it continues, go to **Settings → Apps → Advanced app settings → App execution aliases** and turn off the two **python** aliases. |
| `git`, `node` or `npm is not recognized` | Close and reopen PowerShell after installing. If it continues, rerun the `winget install` line from Lab 0. |
| `password authentication failed for user "postgres"` | The password in `backend\.env` does not match. Fix it in Notepad and check the special-character note in Lab 3. |
| `connection refused` or `could not connect to server` | The database is not running. Run `Get-Service postgresql* \| Start-Service` in an admin PowerShell. |
| `Extra inputs are not permitted` | `backend\.env` has a setting other than `DATABASE_URL` and `NVD_API_KEY`. Remove the extra line. |
| `ModuleNotFoundError` | The `(.venv)` is not active. Run `.\.venv\Scripts\Activate.ps1` from the backend folder. |
| `address already in use` or `port 8000 is in use` | An old copy is still running. Close the other window, or run `Stop-Process -Name python -Force`. |
| The browser page loads but shows no data | The backend window (window 1) is not running or shows an error. Start it again. |
| AI answers are very slow | Ask one question and wait for the model to load. On 8 GB of RAM, use the 3b model from Lab 6. |
| The Ask page says it can't answer | Try a shortcut button or reword with words like "critical", "patch first", "past due", a department name or "network devices". Then file it as feedback. |

Still stuck? Open an issue with a screenshot of the red text.
