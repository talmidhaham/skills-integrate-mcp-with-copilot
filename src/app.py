"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path
import json
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.responses import JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED
import secrets

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")
security = HTTPBasic()

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}

# Load teacher credentials from teachers.json
def load_teachers():
    teachers_path = os.path.join(current_dir, "teachers.json")
    with open(teachers_path, "r") as f:
        data = json.load(f)
    return data["teachers"]

# Simple session store (in-memory)
logged_in_teachers = set()

def authenticate_teacher(credentials: HTTPBasicCredentials = Depends(security)):
    teachers = load_teachers()
    for teacher in teachers:
        if credentials.username == teacher["username"] and secrets.compare_digest(credentials.password, teacher["password"]):
            logged_in_teachers.add(credentials.username)
            return credentials.username
    raise HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Basic"},
    )

def require_teacher(request: Request):
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Not authenticated")
    scheme, _, param = auth.partition(" ")
    if scheme.lower() != "basic":
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    import base64
    try:
        decoded = base64.b64decode(param).decode()
        username, _, password = decoded.partition(":")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid auth header")
    teachers = load_teachers()
    for teacher in teachers:
        if username == teacher["username"] and secrets.compare_digest(password, teacher["password"]):
            return username
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities



# Only teachers can register students
@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str, request: Request):
    teacher = require_teacher(request)
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")
    activity = activities[activity_name]
    if email in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is already signed up")
    activity["participants"].append(email)
    return {"message": f"Teacher {teacher} signed up {email} for {activity_name}"}



# Only teachers can unregister students
@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, request: Request):
    teacher = require_teacher(request)
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")
    activity = activities[activity_name]
    if email not in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")
    activity["participants"].remove(email)
    return {"message": f"Teacher {teacher} unregistered {email} from {activity_name}"}

# Login endpoint for teachers
@app.post("/login")
def login(credentials: HTTPBasicCredentials = Depends(security)):
    username = authenticate_teacher(credentials)
    return {"message": f"Logged in as {username}"}

# Logout endpoint for teachers
@app.post("/logout")
def logout(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    if username in logged_in_teachers:
        logged_in_teachers.remove(username)
        return {"message": f"Logged out {username}"}
    return JSONResponse(status_code=400, content={"message": "Not logged in"})
