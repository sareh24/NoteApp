from fastapi import FastAPI
from app.database import engine, Base
from app.routers import auth, notes
from fastapi.middleware.cors import CORSMiddleware

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Notes API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(notes.router)

@app.get("/")
def root():
    return {"message": "Secure Notes API is running"}