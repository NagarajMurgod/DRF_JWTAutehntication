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
| `/auth/signup/`                       | `POST`  | Used to create a new user account. Requires user details such as username, email, and password.                           |
| `/auth/activate/<uidb64>/<token>/`     | `GET`   | Activates the user account using the unique uidb64 and token sent to the user's email upon registration. |
| `/auth/login/`                        | `POST`  | Authenticates the user and returns a JWT token for sessionless authentication.                        |
| `/auth/logout/`                       | `POST`  | Logout the user and invalidate the JWT token.        |
| `/auth/token/refresh/`                | `POST`  | Refresh the JWT token when it's expired.             |
| `/auth/forgotpassword/`               | `POST`  | Request a password reset link.                       |
| `/auth/passwordreset/<uidb64>/<token>/`| `POST`  | Allows the user to reset their password by providing the uidb64 and reset token   |
| `/auth/profile/`                      | `GET`   | View or update the authenticated user's profile.     |
