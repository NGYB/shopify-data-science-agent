# STRIDE Threat Model Assessment - Shopify Data Science Agent

This document presents a threat modeling assessment of the Shopify Data Science Agent codebase based on the **STRIDE** methodology.

---

## 1. System Boundaries & Data Flow

The agent operates as an ADK 2.0 Graph Workflow. The boundaries and components mapped from [app/agent.py](file:///Users/ngyibin/Documents/Documents%20-%20YB%20MacBook%20Pro/Programs/agy2-projects/shopify-data-science-agent/app/agent.py) are as follows:

*   **Entry Points**:
    *   Client API Endpoints (FastAPI `POST /run_sse` or local runner interface).
    *   User chat inputs (processed as `types.Content`).
*   **Process Boundaries**:
    *   Local Python Execution Environment running the ADK graph.
    *   Vertex AI Gemini API (`gemini-2.5-flash`) for query classification, SQL generation, and SQL-to-Python conversion.
    *   Python `exec()` context running pandas calculations on the host environment.
*   **Data Storage**:
    *   Local Shopify customer CSV dataset (`data/*.csv`).
    *   Local ADK SQLite database (`app/.adk/session.db`) containing conversation histories, states, and event logs.

---

## 2. STRIDE Threat Assessment

### 👥 Spoofing (Identity)
*   **Threat**: Unauthorized users spoofing credentials or session IDs to hijack active sessions and approve dangerous SQL queries or security overrides.
*   **Analysis**:
    *   In the local playground, the FastAPI app runs on `localhost:8080` without authentication.
    *   In a multi-user environment, session IDs (`session_id`) are the primary boundary. If session IDs are predictable, an attacker can access someone else's session.
    *   There is currently no role-based distinction in session resumption: the same session connection that gets the security block can type `"approve"` in the chat box to override it, effectively allowing a regular user to spoof an administrator's authority.
*   **Mitigation Suggestions**:
    *   Implement cryptographic session tokens instead of plain IDs.
    *   Bind authentication contexts (JWT/OAuth) to `Context` and verify user identity in HITL nodes (`approve_sql` and `security_review`) before processing resumes.

### 💾 Tampering (Data Integrity)
*   **Threat 1**: Malicious prompt injections trying to delete, alter, or wipe database files.
    *   *Analysis*: Mitigated by `security_checkpoint` which scans for destructive keywords (e.g. `delete`, `drop`, `truncate`) combined with database nouns (e.g. `data`, `csv`, `file`) and routes them directly to `security_review`.
*   **Threat 2**: Python Code Injection via `exec()` in `execute_python`.
    *   *Analysis*: This is the **highest risk boundary**. The agent converts SQL into Python and runs it using python's `exec()`:
        ```python
        exec(python_code, globals(), loc)
        ```
        If a user manages to inject Python code (e.g., `import os; os.system('rm -rf /')`), it runs with the privileges of the Python process on the host machine.
    *   *Mitigation Suggestions*:
        *   **CRITICAL**: Avoid using `globals()` in the `exec()` context. Use an empty dictionary `{}` for globals to restrict access to built-in functions.
        *   Run the Python execution in a sandboxed, containerized, or restricted subprocess (e.g., Vertex AI Code Interpreter / gRPC sandbox) rather than executing directly on the host application thread.
        *   Implement strict parsing/linting of the generated Python code before execution (e.g., parse AST and reject imports of `os`, `sys`, `subprocess`, `socket`, etc.).

### 🔍 Repudiation (Non-Repudiation)
*   **Threat**: A user or admin overrides a security block or runs a query but denies having performed the action.
*   **Analysis**:
    *   All node completions, user inputs, and HITL decisions are permanently recorded in the sqlite session database (`app/.adk/session.db`) as Event logs.
    *   Security overrides explicitly output: `### ⚠️ Security Alert Override` or `### 🛑 Security Event Blocked`, leaving a clear audit trail.
*   **Mitigation Suggestions**:
    *   Ensure session DB logs are shipped to a read-only logging bucket (e.g., Cloud Logging or GCS bucket) to prevent local log tampering.

### 🔓 Information Disclosure (Confidentiality)
*   **Threat 1**: Sensitive PII (SSNs, Credit Card numbers) leaking into LLM prompts, console logs, or analytics databases.
    *   *Analysis*: Mitigated by `security_checkpoint` which uses regex checks to replace SSNs and Credit Card numbers with `[REDACTED_SSN]` and `[REDACTED_CC]` placeholders before any downstream propagation.
*   **Threat 2**: Stack trace and system pathname leakage.
    *   *Analysis*: If the Python execution fails, it catches exceptions and exposes the raw error:
        ```python
        except Exception as e:
            result_val = f"Error: {e}"
        ```
        Exposing raw Python exceptions directly in the report can leak directory structures, package versions, and schema names.
*   **Mitigation Suggestions**:
    *   Scrub raw tracebacks and display a sanitized user-facing error message in `execute_python` (e.g., `"pandas execution failed due to a type mismatch"` instead of printing raw stack errors).

### ⚡ Denial of Service (Availability)
*   **Threat**: System resource exhaustion (CPU/Memory) or LLM API quota starvation.
*   **Analysis**:
    *   `execute_python` and `process_prediction` load the entire CSV dataset into memory via `pd.read_csv()` on every execution. High-frequency queries or large CSV uploads will crash the container.
    *   Spamming the endpoints will trigger continuous, costly calls to `gemini-2.5-flash`.
*   **Mitigation Suggestions**:
    *   Implement rate-limiting on FastAPI endpoints.
    *   Limit the max size of uploaded CSV datasets.
    *   Cache pandas outputs or read CSV files in chunks if the dataset grows.

### 🔑 Elevation of Privilege (Access Control)
*   **Threat**: Bypassing access controls to execute unauthorized commands or read privileged CSV fields.
*   **Analysis**:
    *   Once a user has session access, they can approve SQL and bypass the admin security checkpoint because the graph assumes that whoever answers the `RequestInput` is the authorized agent.
*   **Mitigation Suggestions**:
    *   Implement role-based authorization scopes (`user` vs. `admin`) and validate these inside the HITL nodes.

---

## 3. High-Priority Vulnerability Action Items

| STRIDE Pillar | Vulnerability | Severity | Recommended Fix |
| :--- | :--- | :---: | :--- |
| **Tampering** | Unsandboxed `exec()` on host system | **CRITICAL** | Transition to a sandboxed Vertex AI Code Interpreter or parse AST to block import statements. |
| **Elevation of Privilege** | Shared HITL role execution | **HIGH** | Bound JWT user roles to session context and verify privilege scope in `approve_sql` and `security_review`. |
| **Information Disclosure** | Raw stack trace exposure | **MEDIUM** | Sanitize exception messages returned by `execute_python` before rendering to the user. |
