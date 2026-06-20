___
# WMS System Design
This document is for designing the WMS system.
## Tech Stack
- Python
- uv
- fastapi
- uvicorn
- mongodb

## Services
 - ### Auth Service
    - #### routes
        - POST /auth/register
        - POST /auth/login
        - POST /auth/logout
        - GET /auth/profile
        - POST /auth/refresh
        - POST /auth/forgot-password
        - POST /auth/change-password
        - POST /auth/reset-password

    - #### user document
    ```json
    {
        "_id":"5c7fdbd4-0a23-4ed2-b5bf-06be8c4f8483",
        "name":"Tushar Kanti Acharyya",
        "email":"tushar.codespace@gmail.com",
        "hashed_password":"hffyguR%^$%$gfuyfwg...",
        "roles":["user"],
        "permissions":[],
        "status":"pending_varification",
        "failed_login_attempts":0,
        "lockout_until": null,
        "multi_Factor_auth":{
            "enable" : false,
            "secret": null
        },
        "created_at": "2026-06-20T...",
        "updated_at": "2026-06-20T..."
    }
    ```