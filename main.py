from datetime import datetime, timezone, date
import httpx
import os
import hmac
import hashlib
from urllib.parse import urlparse
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Header
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select, func
from fastapi.middleware.cors import CORSMiddleware

from aggregator import fetch_data_repository_stats
from database import get_current_user, get_session
from email_service import send_reset_password_email

# Import models so SQLModel registers them
from models import (
    DailyLog,
    DailyLogCreate,
    DailyLogUpdate,
    PasswordResetConfirm,
    Project,
    ProjectCreate,
    ProjectUpdate,
    Task,
    TaskCreate,
    TaskUpdate,
    TokenResponse,
    User,
    UserCreate,
    UserResponse,
    DailyProjectMetric,
)

# Import security helper blocks
from security import (
    create_access_token,
    create_password_reset_token,
    hash_password,
    verify_password,
    verify_password_reset_token,
)

app = FastAPI(
    title="DevPulse",
    description="The core backend API engine for the DevPulse Developer Dashboard",
    version="0.1.0",
)

frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
origins = [
    "http://localhost:5173",
    frontend_url
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allow GET, POST, OPTIONS, PATCH, DELETE
    allow_headers=["*"],  # Allow headers like Authorization and Content-Type
)

# This event runner triggers exactly when the API boots up
# @app.on_event("startup")
# def on_startup():
#     # This creates our tables in PostgreSQL if they don't exist yet!
#     SQLModel.metadata.create_all(engine)


@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "Welcome to the DevPulse Backend Core Engine",
    }


# REGISTER A NEW USER
@app.post("/auth/register", response_model=UserResponse, status_code=201)
def register_user(user_data: UserCreate, session: Session = Depends(get_session)):
    # 1. DEFENSIVE CHECK: Verify email isn't already taken
    existing_user = session.exec(
        select(User).where(User.email == user_data.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=400, detail="A user with this email already exists."
        )

    # 2. Cryptographically hash the plain text input password
    secure_hash = hash_password(user_data.password)

    # 3. Save the secure user profile instance to the database container
    db_user = User(email=user_data.email, hashed_password=secure_hash)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


# LOGIN & GENERATE SECURITY AUTHENTICATION TOKEN
@app.post("/auth/login", response_model=TokenResponse)
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    # 1. Find user by email profile query match
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid email or password credentials."
        )

    # 2. Verify incoming password text against database hash footprint match
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=400, detail="Invalid email or password credentials."
        )

    # 3. Generate secure access verification token signature claims payload
    token = create_access_token(data={"sub": str(user.id), "email": user.email})

    return {"access_token": token, "token_type": "bearer"}


# NEW ROUTE: Create a brand new project record
@app.post("/projects", response_model=Project, status_code=201)
def create_project(
    project_data: ProjectCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # 1. Convert the inbound ProjectCreate validation object into a true Project DB entry
    db_project = Project.model_validate(
        project_data, update={"user_id": current_user.id}
    )
    db_project.user_id = current_user.id

    # 2. Stage the object inside our current database session transaction
    session.add(db_project)

    # 3. Write it out to the physical PostgreSQL database
    session.commit()

    # 4. Refresh our local variable so it grabs the DB-generated ID and timestamp
    session.refresh(db_project)

    if db_project.repository_url:
        background_tasks.add_task(fetch_data_repository_stats, db_project.id)

    # 5. Return the full database record back to the frontend
    return db_project


# GET ALL PROJECTS (With Professional Pagination)
@app.get("/projects", response_model=list[Project])
def read_projects(
    offset: int = 0,  # Default starting point for pagination, offset=0 means start from the first record
    limit: int = Query(
        default=10, le=100
    ),  # Default 10 records, maximum 100, le means "less than or equal to"
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # 1. Construct an SQL SELECT statement
    statement = (
        select(Project)
        .where(Project.user_id == current_user.id)
        .offset(offset)
        .limit(limit)
    )  # It means "skip the first 'offset' records and then take the next 'limit' records"

    # 2. Execute the query against PostgreSQL and collect the results
    projects = session.exec(
        statement
    ).all()  # The .all() method fetches all the results of the executed query and returns them as a list of Project objects

    # 3. Return the array list
    return projects


# GET A SINGLE PROJECT BY ID (With Clean Error Handling)
@app.get("/projects/{project_id}", response_model=Project)
def read_project(
    project_id: int,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # This line uses FastAPI's dependency injection to provide a database session to the route handler

    # 1. Search the table directly using the primary key ID
    project = session.get(
        Project, project_id
    )  # Can search by primary key directly, and also returns None if the record doesn't exist

    # 2. DEFENSIVE PROGRAMMING: If the ID doesn't exist, raise a clean HTTP 404 Exception
    if not project or project.user_id != current_user.id:
        raise HTTPException(
            status_code=404,
            detail=f"Project with ID {project_id} not found or unauthorized.",
        )

    # TRIGGER BACKGROUND ASYNC SYNC:
    # If a repository URL exists, enqueue the background synchronization routine.
    # This sends the response to the user instantly while running the task in the background.
    if project.repository_url:
        background_tasks.add_task(fetch_data_repository_stats, project.id)

    # 3. Otherwise, return the target record data
    return project


@app.patch("/projects/{project_id}", response_model=Project)
def update_project(
    project_id: int,
    project_data: ProjectUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_project = session.get(Project, project_id)
    if not db_project or db_project.user_id != current_user.id:
        raise HTTPException(
            status_code=404, detail="Project not found or unauthorized."
        )

    # Extract incoming payload and apply partial updates to database state records
    update_dict = project_data.model_dump(exclude_unset=True)
    db_project.sqlmodel_update(update_dict)

    session.add(db_project)
    session.commit()
    session.refresh(db_project)
    return db_project


@app.delete("/projects/{project_id}", status_code=200)
def delete_project(
    project_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_project = session.get(Project, project_id)
    if not db_project or db_project.user_id != current_user.id:
        raise HTTPException(
            status_code=404, detail="Project not found or unauthorized."
        )

    session.delete(db_project)
    session.commit()
    return {
        "message": f"Project '{db_project.name}' and all associated tasks deleted successfully."
    }


@app.get("/projects/{project_id}/github/loc")
async def get_github_loc(
    project_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    project = session.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found or unauthorized.")
        
    if not project.repository_url:
        return {"lines_written": 0}
        
    # Get midnight today UTC
    today = datetime.now(timezone.utc).date()
    
    # Query the database instead of asking GitHub API directly!
    metric = session.exec(
        select(DailyProjectMetric)
        .where(DailyProjectMetric.project_id == project.id)
        .where(DailyProjectMetric.date_recorded == today)
    ).first()
    
    if metric:
        return {"lines_written": metric.lines_added}
        
    return {"lines_written": 0}


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    session: Session = Depends(get_session),
):
    # 1. SECURITY: Validate that this request actually came from GitHub!
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="Server webhook secret not configured")
        
    if not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Missing signature")
        
    payload_body = await request.body()
    signature = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    expected_signature = f"sha256={signature}"
    
    if not hmac.compare_digest(x_hub_signature_256, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 2. PARSE PAYLOAD
    payload = await request.json()
    
    # We only care about push events
    if "commits" not in payload or "repository" not in payload:
        return {"status": "ignored", "reason": "Not a push event or missing data"}
        
    repo_url = payload["repository"].get("html_url")
    print(f"🔔 [WEBHOOK] Received push event for repo: {repo_url}")
    if not repo_url:
        return {"status": "ignored", "reason": "No repo URL"}
        
    # Find matching project in our database (case-insensitive!)
    project = session.exec(
        select(Project).where(func.lower(Project.repository_url) == repo_url.lower())
    ).first()
    
    if not project:
        print(f"🔔 [WEBHOOK] Project {repo_url} not found in DB!")
        return {"status": "ignored", "reason": "Project not tracked in DevPulse"}

    print(f"🔔 [WEBHOOK] Match found! Updating project ID {project.id} ({project.name})")

    total_additions = 0
    commits = payload.get("commits", [])
    repo_full_name = payload["repository"].get("full_name")
    
    # The payload does not contain exact additions, so we must fetch each commit's stats
    async with httpx.AsyncClient() as client:
        for commit in commits:
            commit_id = commit.get("id")
            if commit_id and repo_full_name:
                commit_api_url = f"https://api.github.com/repos/{repo_full_name}/commits/{commit_id}"
                try:
                    detail_res = await client.get(commit_api_url)
                    if detail_res.status_code == 200:
                        stats = detail_res.json().get("stats", {})
                        total_additions += stats.get("additions", 0)
                except Exception as e:
                    print(f"🔔 [WEBHOOK] Error fetching stats for commit {commit_id}: {e}")

    if total_additions > 0:
        today = datetime.now(timezone.utc).date()
        
        # Check if we already have a metric row for today
        metric = session.exec(
            select(DailyProjectMetric)
            .where(DailyProjectMetric.project_id == project.id)
            .where(DailyProjectMetric.date_recorded == today)
        ).first()
        
        if metric:
            metric.lines_added += total_additions
        else:
            metric = DailyProjectMetric(
                project_id=project.id,
                date_recorded=today,
                lines_added=total_additions
            )
            
        session.add(metric)
        
    # Also update the project's latest commit message dynamically from the push payload!
    if commits:
        latest_message = commits[-1].get("message")
        if latest_message:
            project.last_commit_message = latest_message.split("\n")[0]
            session.add(project)
            
    session.commit()

    return {"status": "success", "lines_added": total_additions}

@app.post("/tasks", response_model=Task, status_code=201)
def create_task(
    task_data: TaskCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # 1. DEFENSIVE CHECK: Verify the parent project actually exists first
    parent_project = session.get(Project, task_data.project_id)
    if not parent_project or parent_project.user_id != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="Cannot create task. Associated project does not exist or is unauthorized.",
        )

    # 2. Convert schema data to database record model
    db_task = Task.model_validate(task_data)

    # 3. Commit transactions
    session.add(db_task)
    session.commit()
    session.refresh(db_task)

    return db_task


# GET ALL TASKS FOR A SPECIFIC PROJECT
@app.get("/projects/{project_id}/tasks", response_model=list[Task])
def read_project_tasks(
    project_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # 1. Check if the project exists
    project = session.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="Project not found or unauthorized.",
        )

    # 2. Return the tasks list directly via our SQLModel Relationship back-population!
    return project.tasks


@app.patch("/tasks/{task_id}", response_model=Task)
def update_task(
    task_id: int,
    task_data: TaskUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_task = session.get(Task, task_id)
    if not db_task or db_task.project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found or unauthorized.")

    update_dict = task_data.model_dump(exclude_unset=True)
    db_task.sqlmodel_update(update_dict)

    session.add(db_task)
    session.commit()
    session.refresh(db_task)
    return db_task


@app.delete("/tasks/{task_id}", status_code=200)
def delete_task(
    task_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_task = session.get(Task, task_id)
    if not db_task or db_task.project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found or unauthorized.")

    session.delete(db_task)
    session.commit()
    return {"message": "Task deleted successfully."}


@app.post("/tasks/{task_id}/start_timer", response_model=Task)
def start_task_timer(
    task_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_task = session.get(Task, task_id)
    if not db_task or db_task.project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found or unauthorized.")
        
    db_task.session_start_time = datetime.now(timezone.utc)
    session.add(db_task)
    session.commit()
    session.refresh(db_task)
    return db_task


@app.post("/tasks/{task_id}/stop_timer", response_model=Task)
def stop_task_timer(
    task_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_task = session.get(Task, task_id)
    if not db_task or db_task.project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Task not found or unauthorized.")
        
    if not db_task.session_start_time:
        raise HTTPException(status_code=400, detail="Timer was not started for this task.")
        
    # Ensure session_start_time is timezone-aware if the DB returns it naive
    start_time = db_task.session_start_time
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
        
    time_diff = datetime.now(timezone.utc) - start_time
    hours_spent = time_diff.total_seconds() / 3600.0
    
    db_task.time_spent += hours_spent
    db_task.session_start_time = None
    
    session.add(db_task)
    session.commit()
    session.refresh(db_task)
    return db_task


@app.post("/logs", response_model=DailyLog, status_code=200)
def create_daily_log(
    log_data: DailyLogCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):

    # 1. DEFENSIVE CHECK: Verify the target project exists
    project = session.get(Project, log_data.project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="Cannot create log. Associated project does not exist or is unauthorized.",
        )

    # 2. Convert and stage
    db_log = DailyLog.model_validate(log_data)
    session.add(db_log)
    session.commit()
    session.refresh(db_log)

    return db_log


# GET ALL DAILY LOGS (With Pagination)
@app.get("/logs", response_model=list[DailyLog])
def read_daily_logs(
    offset: int = 0,
    limit: int = Query(default=30, le=100),  # Default to last 30 logs (approx a month)
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    statement = (
        select(DailyLog)
        .join(Project)
        .where(Project.user_id == current_user.id)
        .offset(offset)
        .limit(limit)
    )
    return session.exec(statement).all()


@app.patch("/logs/{log_id}", response_model=DailyLog)
def update_daily_log(
    log_id: int,
    log_data: DailyLogUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_log = session.get(DailyLog, log_id)
    if not db_log or db_log.project.user_id != current_user.id:
        raise HTTPException(
            status_code=404, detail="Daily log entry not found or unauthorized."
        )

    update_dict = log_data.model_dump(exclude_unset=True)
    db_log.sqlmodel_update(update_dict)

    session.add(db_log)
    session.commit()
    session.refresh(db_log)
    return db_log


@app.delete("/logs/{log_id}", status_code=200)
def delete_daily_log(
    log_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    db_log = session.get(DailyLog, log_id)
    if not db_log or db_log.project.user_id != current_user.id:
        raise HTTPException(
            status_code=404, detail="Daily log entry not found or unauthorized."
        )

    session.delete(db_log)
    session.commit()
    return {"message": "Daily log entry deleted successfully."}


@app.post("/auth/forgot-password", status_code=200)
async def forgot_password(email: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.email == email)).first()

    # Defensive check remains identical to preserve security obfuscation barriers
    if not user:
        return {
            "message": "If the email is registered, a password reset link has been dispatched."
        }

    # Generate the security token hash
    reset_token = create_password_reset_token(user.email)

    # PRODUCTION EMAIL TRIGGER: Await the background network handshake
    try:
        await send_reset_password_email(user.email, reset_token)
    except Exception as e:
        # Prevent internal mailing infrastructure connection errors from breaking the user flow
        print(f"[SERVER ERROR] Failed to deliver notification mail: {e}")
        raise HTTPException(status_code=500, detail="Email delivery engine failed.")

    return {
        "message": "If the email is registered, a password reset link has been dispatched."
    }


@app.post("/auth/reset-password", status_code=200)
def reset_password(data: PasswordResetConfirm, session: Session = Depends(get_session)):
    # Validate token structural integrity and expiration timestamps
    email = verify_password_reset_token(data.token)
    if not email:
        raise HTTPException(
            status_code=400,
            detail="The password reset token is invalid or has expired.",
        )

    # Find the user target profile row mapping
    user = session.exec(select(User).where(User.email == email)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User profile resource not found.")

    # Hash the fresh password string and update the database context
    user.hashed_password = hash_password(data.new_password)

    session.add(user)
    session.commit()

    return {"message": "Your password has been successfully updated."}
