from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import status
from pydantic import BaseModel
from pydantic import BaseSettings

app = FastAPI()


class Settings(BaseSettings):
    database_url: str
    secret_key: str

    class Config:
        env_file = ".env"


settings = Settings()

SECRET_KEY = settings.secret_key
SQLALCHEMY_DATABASE_URL = settings.database_url

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class GoalDB(Base):
    __tablename__ = "goals"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    due_date = Column(DateTime)
    progress = Column(Integer)
    completed = Column(Boolean, default=False)


class Goal(BaseModel):
    title: str
    due_date: datetime
    progress: int
    completed: bool

    class Config:
        orm_mode = True


Base.metadata.create_all(bind=engine)


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return username


async def authenticate_user(username: str, password: str):
    # Implement user authentication logic here
    return True


async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password

    user = await authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/goals/", response_model=Goal)
async def create_goal(goal: Goal, current_user: str = Depends(get_current_user), db: Session = Depends(get_db), ):
    db_goal = GoalDB(title=goal.title, due_date=goal.due_date,
                     progress=goal.progress)
    db.add(db_goal)
    db.commit()
    db.refresh(db_goal)
    return db_goal


@app.get("/goals/")
async def read_goals(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    goals = db.query(GoalDB).all()
    return goals


@app.put("/goals/{goal_id}", response_model=Goal)
async def update_goal(goal_id: int, goal: Goal, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    db_goal = db.query(GoalDB).filter(GoalDB.id == goal_id).first()
    if db_goal is None:
        raise HTTPException(status_code=404, detail="Goal not found")
    db_goal.title = goal.title
    db_goal.due_date = goal.due_date
    db_goal.progress = goal.progress
    db_goal.completed = goal.completed
    db.commit()
    db.refresh(db_goal)
    return db_goal


@app.delete("/goals/{goal_id}")
async def delete_goal(goal_id: int, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    db_goal = db.query(GoalDB).filter(GoalDB.id == goal_id).first()
    if db_goal is None:
        raise HTTPException(status_code=404, detail="Goal not found")
    db.delete(db_goal)
    db.commit()
    return {"message": "Goal deleted successfully"}
