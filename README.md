# JWT Authentication API with Django REST Framework
This project provides a JWT authentication system implemented with Django REST Framework (DRF), allowing users to authenticate and interact with your API securely using JSON Web Tokens.


## Features
- **JWT Authentication**: Users can sign up, log in, and obtain a JWT for secure authentication.
- **Secure Token Management**: Use JWT tokens for sessionless authentication.
- **Django REST Framework** : The backend is built using Django REST Framework, providing an easy-to-use and powerful API.
- **Rate Limit** : Only 10 requests per minute for forgot password end point 
- **Swagger Documentation**: The project includes Swagger for automatic API documentation, making it easy to explore and interact with your API's endpoints directly from a browser.

## Installation
1. Clone the repository

    ```
    https://github.com/NagarajMurgod/DRF_JWTAutehntication.git
    cd DRF_JWTAutehntication
    ```

2. Create a virtual environment and install dependencies:

    ```
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    ```

3.  Set up the database (PostgreSQL):

    - Ensure PostgreSQL is running, and create a new database for the project.
    - Update the database configuration in backend/settings.py with your database credentials.


4. Run migrations to set up the database schema:

    ```
    cd src
    python manage.py migrate
    ```

5. Create a superuser (for admin access):

    ```
    python manage.py createsuperuser
    ```

6. Start the backend server:

    ```
    python manage.py runserve
    ```

## API Endpoints


| Endpoint                                   | Method  | Description                                          |
|--------------------------------------------|---------|------------------------------------------------------|
| `/api/auth/signup/`                       | `POST`  | Create a new user account.                           |
| `/api/auth/activate/<uidb64>/<token>/`     | `GET`   | Activate a user account using a unique ID and token. |
| `/api/auth/login/`                        | `POST`  | Login to obtain a JWT token.                         |
| `/api/auth/logout/`                       | `POST`  | Logout the user and invalidate the JWT token.        |
| `/api/auth/token/refresh/`                | `POST`  | Refresh the JWT token when it's expired.             |
| `/api/auth/forgotpassword/`               | `POST`  | Request a password reset link.                       |
| `/api/auth/passwordreset/<uidb64>/<token>/`| `POST`  | Reset the forgotten password using a unique token.  |
| `/api/auth/profile/`                      | `GET`   | View or update the authenticated user's profile.     |
