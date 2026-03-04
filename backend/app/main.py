from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routers import auth

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Notes API")

# Add CORS middleware BEFORE routing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (change in production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)

@app.get("/")
def root():
    return {"message": "Secure Notes API is running"}