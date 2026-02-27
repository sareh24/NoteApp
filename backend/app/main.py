from fastapi import FastAPI
from app.database import engine, Base
from app.routers import auth

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Notes API")

# Include routers
app.include_router(auth.router)

@app.get("/")
def root():
    return {"message": "Secure Notes API is running"}