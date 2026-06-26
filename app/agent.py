# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import glob
import os
import re

import pandas as pd
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.apps import App
from google.adk.events.event import Event, EventActions
from google.adk.events.request_input import RequestInput
from google.adk.workflow import START, Edge, Workflow, node
from google.genai import types
from pydantic import BaseModel, Field
from sklearn.linear_model import LogisticRegression

from app import config

load_dotenv()

# Authentication setup
use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "TRUE").upper() == "TRUE"
if use_vertex:
    import google.auth

    try:
        _, project_id = google.auth.default()
        if project_id:
            os.environ.setdefault("GOOGLE_CLOUD_PROJECT", project_id)
    except Exception:
        pass
    os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "us-east1")

# Regex patterns for sensitive PII scrubbing
SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_REGEX = re.compile(r"\b(?:\d[- ]?){13,16}\b")


def _extract_string_value(val) -> str | None:
    if val is None:
        return None
    if isinstance(val, dict):
        for key in ["response", "approval", "security_override", "text", "value"]:
            if key in val:
                return str(val[key])
        if val:
            return str(next(iter(val.values())))
        return None
    return str(val)


# Pydantic models for structured outputs
class ClassificationOutput(BaseModel):
    question_type: str = Field(
        description="Must be either 'historical' (for historical data questions) or 'predictive' (for future/predictions)."
    )
    query: str = Field(description="The cleaned user query.")


class SqlGenerationOutput(BaseModel):
    sql_query: str = Field(
        description="Generated raw SQL query without any markdown code block wrap."
    )


class PythonCodeOutput(BaseModel):
    python_code: str = Field(
        description="Executable Python code. Assumes a pandas DataFrame named 'df' contains the customer/order data. Store the final result in a variable named 'result' or print it. For example: result = df['customer_id'].nunique(). Do not include markdown code blocks or explanations."
    )


# Graph Nodes


# 0. Security Checkpoint Node (Function Node)
@node
def security_checkpoint(ctx: Context, node_input: types.Content):
    query = ""
    if node_input and node_input.parts:
        query = node_input.parts[0].text or ""

    # Check if we are resuming a pending HITL step
    is_resuming = False
    if ctx.resume_inputs:
        is_resuming = True
    elif query.strip().lower() in ["approve", "reject", "block", "yes", "no"]:
        is_resuming = True

    if is_resuming and ctx.state.get("query"):
        saved_query = ctx.state.get("query")
        clean_content = types.Content(
            role="user", parts=[types.Part.from_text(text=saved_query)]
        )
        route = "flagged" if ctx.state.get("security_flagged") else "clean"

        # If the user typed the response in the chat box, save it as state override
        state_delta = {}
        cleaned_query = query.strip().lower()
        if cleaned_query in ["approve", "reject"]:
            state_delta["user_approval_override"] = cleaned_query
        elif cleaned_query in ["block", "override"]:
            state_delta["security_override_override"] = cleaned_query
        elif cleaned_query in ["yes", "no"]:
            mapped = "approve" if cleaned_query == "yes" else "reject"
            state_delta["user_approval_override"] = mapped
            state_delta["security_override_override"] = (
                "approve" if cleaned_query == "yes" else "block"
            )

        yield Event(
            output=clean_content,
            actions=EventActions(route=route, state_delta=state_delta),
        )
        return

    # 1. PII Scrubbing (SSNs and Credit Cards)
    scrubbed_query, ssn_count = SSN_REGEX.subn("[REDACTED_SSN]", query)
    scrubbed_query, cc_count = CC_REGEX.subn("[REDACTED_CC]", scrubbed_query)

    redacted_categories = []
    if ssn_count > 0:
        redacted_categories.append("ssn")
    if cc_count > 0:
        redacted_categories.append("credit_card")

    # 2. Malicious Prompt Injection Check
    lower_query = scrubbed_query.lower()
    injection_keywords = [
        "delete",
        "drop",
        "truncate",
        "wipe",
        "overwrite",
        "modify",
        "remove",
        "alter",
        "clear",
        "erase",
        "destroy",
    ]
    target_keywords = [
        "data",
        "dataset",
        "file",
        "csv",
        "table",
        "database",
        "files",
        "records",
        "folder",
        "directory",
    ]

    has_injection = False
    for inj in injection_keywords:
        if inj in lower_query:
            for tgt in target_keywords:
                if tgt in lower_query:
                    has_injection = True
                    break

    if has_injection:
        # Route to security_review node
        yield Event(
            output=scrubbed_query,
            actions=EventActions(
                route="flagged",
                state_delta={
                    "query": scrubbed_query,
                    "redacted_categories": redacted_categories,
                    "security_flagged": True,
                },
            ),
        )
    else:
        # Rebuild clean content to pass downstream to the LlmAgent
        clean_content = types.Content(
            role="user", parts=[types.Part.from_text(text=scrubbed_query)]
        )
        yield Event(
            output=clean_content,
            actions=EventActions(
                route="clean",
                state_delta={
                    "query": scrubbed_query,
                    "redacted_categories": redacted_categories,
                    "security_flagged": False,
                },
            ),
        )


# 0.1 Security Review Node (Function Node with HITL, rerun_on_resume=True)
@node(rerun_on_resume=True)
async def security_review(ctx: Context, node_input: str):
    query = node_input
    override = (
        _extract_string_value(ctx.resume_inputs.get("security_override"))
        if ctx.resume_inputs
        else None
    )

    if not override and ctx.state.get("security_override_override"):
        override = ctx.state.get("security_override_override")

    if not override:
        yield RequestInput(
            interrupt_id="security_override",
            message=(
                f"🚨 **Security Alert: Malicious Prompt Injection Flagged** 🚨\n\n"
                f"The following user query has been blocked by the security checkpoint:\n"
                f"Query: `{query}`\n\n"
                f"Do you want to override this flag and allow the query, or block it? (reply with 'approve' or 'block')"
            ),
        )
        return

    redacted = ctx.state.get("redacted_categories", [])
    redacted_str = f", Redacted categories: {redacted}" if redacted else ""

    state_delta = {}
    if "security_override_override" in ctx.state:
        state_delta["security_override_override"] = None

    if override.strip().lower() == "approve":
        report = (
            f"### ⚠️ Security Alert Override\n\n"
            f"**Flagged Query:** `{query}`\n"
            f"**Action:** Overridden by Administrator. WARNING: Query may be unsafe.\n"
            f"**Session state**:{redacted_str}"
        )
    else:
        report = (
            f"### 🛑 Security Event Blocked\n\n"
            f"**Flagged Query:** `{query}`\n"
            f"**Action:** Blocked. Malicious attempt to delete or modify data has been prevented.\n"
            f"**Session state**:{redacted_str}"
        )

    yield Event(output=report, actions=EventActions(state_delta=state_delta))


# 1. Classification Node (LlmAgent)
classify_question = LlmAgent(
    name="classify_question",
    model=config.LLM_MODEL_NAME,
    instruction=(
        "You are a routing assistant. Classify the user query into one of two business question types:\n"
        "1. 'historical': questions about historical store data (e.g., past sales, signup counts, orders, customers).\n"
        "2. 'predictive': questions about the future (e.g., forecasting, predicting customer churn, identifying who will churn).\n"
        "Respond strictly with the classification schema."
    ),
    output_schema=ClassificationOutput,
    output_key="classification",
)


# 2. Router Node (Function Node)
@node
def router(node_input: dict):
    q_type = node_input.get("question_type", "historical")
    query = node_input.get("query", "")

    if q_type == "predictive":
        return Event(output=query, actions=EventActions(route="predictive"))
    return Event(output=query, actions=EventActions(route="historical"))


# 3. SQL Generator Node (LlmAgent)
generate_sql = LlmAgent(
    name="generate_sql",
    model=config.LLM_MODEL_NAME,
    instruction=(
        "You are an expert Shopify Database Engineer. Generate a SQL query to answer the user's historical "
        "data question based on typical Shopify schemas (orders, customers, gmv, etc.). Return only the raw SQL "
        "query. Do not wrap in markdown or add explanations."
    ),
    output_schema=SqlGenerationOutput,
    output_key="generated_sql",
)


# 4. SQL Approval Node (Function Node with HITL, rerun_on_resume=True)
@node(rerun_on_resume=True)
async def approve_sql(ctx: Context, node_input: dict):
    sql_query = node_input.get("sql_query", "")

    # Store or retrieve the query from the workflow state
    sql_query = ctx.state.get("pending_sql") or sql_query.strip()

    # Check for human feedback
    approval = (
        _extract_string_value(ctx.resume_inputs.get("approval"))
        if ctx.resume_inputs
        else None
    )

    if not approval and ctx.state.get("user_approval_override"):
        approval = ctx.state.get("user_approval_override")

    if not approval:
        # Save current query to state to protect against LLM non-determinism during resume
        yield Event(actions=EventActions(state_delta={"pending_sql": sql_query}))

        # Halt execution and request input from user
        redacted = ctx.state.get("redacted_categories", [])
        redacted_notice = (
            f"\n*(Note: Redacted sensitive categories: {redacted})*" if redacted else ""
        )
        yield RequestInput(
            interrupt_id="approval",
            message=(
                f"📋 **SQL Query Approval Request**\n\n"
                f"The following SQL query has been generated to answer your historical data question:\n"
                f"```sql\n{sql_query}\n```\n"
                f"Do you approve or reject this query? (Please reply with 'approve' or 'reject')."
                f"{redacted_notice}"
            ),
        )
        return

    # Clear pending_sql and overrides to prevent leakage to the next question
    state_delta = {"pending_sql": None}
    if "user_approval_override" in ctx.state:
        state_delta["user_approval_override"] = None

    if approval.strip().lower() == "approve":
        yield Event(
            output=sql_query,
            actions=EventActions(route="approved", state_delta=state_delta),
        )
    else:
        yield Event(
            output="### ❌ SQL Query Rejected\n\nThe generated SQL query was rejected by the user. Workflow execution halted.",
            actions=EventActions(route="rejected", state_delta=state_delta),
        )


# 4.1 SQL to Python Conversion Node (LlmAgent)
sql_to_python = LlmAgent(
    name="sql_to_python",
    model=config.LLM_MODEL_NAME,
    instruction=(
        "You are an expert Python data scientist. Convert the input SQL query into equivalent Python code using pandas. "
        "The customer/order data is pre-loaded in a pandas DataFrame named 'df'. The columns of 'df' are:\n"
        "- customer_id (string)\n"
        "- customer_first_name (string)\n"
        "- customer_last_name (string)\n"
        "- order_id (int)\n"
        "- order_name (string)\n"
        "- order_placed_timestamp (datetime, timezone-naive)\n"
        "- fully_paid (bool)\n"
        "- fulfillment_status (string)\n"
        "- net_gmv (float)\n"
        "- currency (string)\n\n"
        "Your code should perform the logic of the SQL query on 'df' and assign the output value (e.g. integer count, DataFrame, or Series) to the variable 'result'. Do not wrap the code in markdown code blocks."
    ),
    output_schema=PythonCodeOutput,
    output_key="python_conversion",
)


# 4.2 Python Execution Node (Function Node)
@node
def execute_python(ctx: Context, node_input: dict) -> str:
    python_code = node_input.get("python_code", "")

    # Locate all CSV files in data/
    csv_files = glob.glob("data/*.csv")
    if not csv_files:
        return "Error: No data files found in the data/ directory."

    file_path = csv_files[0]
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        return f"Error reading data file: {e}"

    df["order_placed_timestamp"] = pd.to_datetime(
        df["order_placed_timestamp"]
    ).dt.tz_localize(None)

    # Execute Python Code
    import io
    import sys

    stdout_capture = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = stdout_capture

    loc = {"df": df, "pd": pd, "result": None}
    execution_error = None
    try:
        exec(python_code, globals(), loc)
        sys.stdout = old_stdout
        captured = stdout_capture.getvalue().strip()

        if captured:
            result_val = captured
        elif loc.get("result") is not None:
            result_val = str(loc["result"])
        else:
            result_val = "Execution completed, but no printed output or 'result' variable was found."
    except Exception as e:
        sys.stdout = old_stdout
        execution_error = str(e)
        result_val = f"Error: {e}"

    # Format report
    redacted = ctx.state.get("redacted_categories", [])
    redacted_str = (
        f"\n*(Note: Redacted sensitive categories: {redacted})*" if redacted else ""
    )

    report = "### ✅ SQL Query Approved & Executed\n\n"
    report += "**Equivalent Python Code Run:**\n"
    report += f"```python\n{python_code}\n```\n\n"

    if execution_error:
        report += "❌ **Execution Failed:**\n"
        report += f"```\n{execution_error}\n```\n"
    else:
        report += "📊 **Execution Output:**\n"
        report += f"```\n{result_val}\n```\n"

    report += redacted_str
    return report


# 5. Predictive Path Node (Function Node)
@node
def process_prediction(node_input: str) -> str:
    # Locate all CSV files in data/
    csv_files = glob.glob("data/*.csv")
    if not csv_files:
        return "Error: No data files found in the data/ directory."

    # Read the preprocessed CSV file
    file_path = csv_files[0]
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        return f"Error reading data file: {e}"

    required_cols = [
        "customer_id",
        "order_placed_timestamp",
        "net_gmv",
        "customer_first_name",
        "customer_last_name",
    ]
    for col in required_cols:
        if col not in df.columns:
            return f"Error: Dataset is missing required column: {col}"

    # Convert timestamps
    df["order_placed_timestamp"] = pd.to_datetime(
        df["order_placed_timestamp"]
    ).dt.tz_localize(None)

    # Calculate date span across entire dataset
    min_date = df["order_placed_timestamp"].min()
    max_date = df["order_placed_timestamp"].max()
    if pd.isnull(min_date) or pd.isnull(max_date):
        return "Error: Could not calculate date span (invalid timestamps)."

    span_days = (max_date - min_date).days

    # Check minimum required threshold from config
    if span_days < config.ML_DATA_THRESHOLD_DAYS:
        return "Insufficient data to generate machine learning model"

    # Build ML churn prediction model
    customer_df = (
        df.groupby("customer_id")
        .agg(
            total_spent=("net_gmv", "sum"),
            order_count=("order_id", "count"),
            last_order_date=("order_placed_timestamp", "max"),
            first_order_date=("order_placed_timestamp", "min"),
            first_name=("customer_first_name", "first"),
            last_name=("customer_last_name", "first"),
        )
        .reset_index()
    )

    # Feature engineering
    customer_df["customer_lifetime_days"] = (
        customer_df["last_order_date"] - customer_df["first_order_date"]
    ).dt.days
    customer_df["recency_days"] = (max_date - customer_df["last_order_date"]).dt.days

    # Label definition: Churned (1) if recency_days > 20 days, Active (0) otherwise
    customer_df["churned"] = (customer_df["recency_days"] > 20).astype(int)

    # Train LogisticRegression model
    features = ["total_spent", "order_count", "customer_lifetime_days"]
    X = customer_df[features].fillna(0)
    y = customer_df["churned"]

    if len(y.unique()) < 2:
        # Fallback to simple rule-based model if target is homogeneous
        customer_df["predicted_churn"] = customer_df["churned"]
    else:
        model = LogisticRegression(random_state=42)
        model.fit(X, y)
        customer_df["predicted_churn"] = model.predict(X)

    # Filter customers predicted to churn
    churn_list = customer_df[customer_df["predicted_churn"] == 1]

    # Format report
    report = "### 🔮 Customer Churn Prediction Report\n\n"
    report += f"- **Dataset analyzed**: `{os.path.basename(file_path)}`\n"
    report += f"- **Time span of dataset**: {span_days} days (from {min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')})\n"
    report += f"- **Total customers analyzed**: {len(customer_df)}\n"
    report += f"- **Customers predicted to churn**: {len(churn_list)}\n\n"

    if len(churn_list) == 0:
        report += (
            "No customers are predicted to churn based on current activity patterns."
        )
    else:
        report += "#### ⚠️ High Risk Churn Customers:\n"
        for _, row in churn_list.iterrows():
            name = (
                f"{row['first_name']} {row['last_name']}"
                if pd.notnull(row["first_name"])
                else "Unknown"
            )
            report += f"- **Customer ID**: `{row['customer_id']}` ({name})\n"
            report += f"  - Total Spent: AUD {row['total_spent']:.2f} | Orders: {row['order_count']} | Recency: {row['recency_days']} days ago\n"

    return report


# 6. Response Formatting Node (Function Node)
@node
def format_response(node_input: str):
    yield Event(
        content=types.Content(
            role="model", parts=[types.Part.from_text(text=node_input)]
        )
    )
    yield Event(output=node_input)


# Constructing the graph-based Workflow
root_agent = Workflow(
    name="shopify_data_science_workflow",
    description="Shopify data science graph assistant with SQL HITL and ML churn modeling.",
    edges=[
        Edge(from_node=START, to_node=security_checkpoint),
        Edge(from_node=security_checkpoint, to_node=classify_question, route="clean"),
        Edge(from_node=security_checkpoint, to_node=security_review, route="flagged"),
        Edge(from_node=classify_question, to_node=router),
        Edge(from_node=router, to_node=generate_sql, route="historical"),
        Edge(from_node=router, to_node=process_prediction, route="predictive"),
        Edge(from_node=generate_sql, to_node=approve_sql),
        Edge(from_node=approve_sql, to_node=sql_to_python, route="approved"),
        Edge(from_node=approve_sql, to_node=format_response, route="rejected"),
        Edge(from_node=sql_to_python, to_node=execute_python),
        Edge(from_node=execute_python, to_node=format_response),
        Edge(from_node=process_prediction, to_node=format_response),
        Edge(from_node=security_review, to_node=format_response),
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
)
