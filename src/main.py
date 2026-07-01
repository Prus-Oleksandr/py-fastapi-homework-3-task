from fastapi import FastAPI

from routes import movie_router, accounts_router

app = FastAPI(title="Movies homework", description="Description of project")

api_version_prefix = "/api/v1"

# main.py
# Прибираємо префікс зовсім, бо ми його зашили всередину кожного роута вручну
app.include_router(accounts_router, tags=["accounts"])
app.include_router(
    movie_router, prefix=f"{api_version_prefix}/theater", tags=["theater"]
)
