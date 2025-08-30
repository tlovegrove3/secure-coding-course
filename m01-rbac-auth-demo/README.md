# RBAC Demo

This project demonstrates Role-Based Access Control (RBAC) in a simple Python application.

## Features
- **Login Simulation:** Uses hardcoded usernames and roles (no password or form input).
- **User Roles:** Two roles are defined: `admin` and `user`.
- **Protected Actions:**
	- Admins can perform all actions (create, read, update, delete).
	- Regular users can only perform read actions.
- **Access Control:**
	- Only admins can access admin actions.
	- Only users can access user actions.

## How It Works
- The script defines a list of users and their roles.
- The `login` function simulates user authentication.
- The `admin_action` and `user_action` functions restrict access based on the current user's role.
- The script tests both a regular user and an admin user, showing the results of their actions.

## CIA Triad Principle
This application demonstrates the principle of **Confidentiality** from the CIA triad by restricting access to sensitive actions based on user roles. Admin users can perform all actions, while regular users have limited access. Authentication is handled by the login function, and authorization is enforced through role-based access control.

## Usage
Run the script with Python:

```pwsh
python rbac_demo.py
```

You will see output for both a regular user and an admin user, showing which actions they are allowed to perform.

## Author
Terry Lovegrove
