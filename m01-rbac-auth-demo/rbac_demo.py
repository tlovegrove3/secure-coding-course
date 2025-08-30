"""
Creator: Terry Lovegrove
Date: 2025-08-29
Purpose: Demonstrate Role-Based Access Control (RBAC) in a Python application

Requirements:
Login simulation

    Use a hardcoded username and role in the script.

    No need for password hashing or form input.

User roles

    Create two user roles (e.g., admin and user) using simple logic or a dictionary.

Protected actions or routes

    Simulate two different functions or endpoints.

    Allow only admin to access one, and only user to access the other.

Code comment or short paragraph

    Explain in a few lines how your app shows one part of the CIA triad (Confidentiality, Integrity, or Availability).
"""

from email import header


roles = {
    "admin": {
        "name": "Administrator",
        "permissions": ["create", "read", "update", "delete"],
    },
    "user": {"name": "Regular User", "permissions": ["read"]},
}

user_list = [
    {"username": "instructor1", "role": "admin"},
    {"username": "student1", "role": "user"},
]


def login(username):
    user = next((u for u in user_list if u["username"] == username), None)
    if user:
        return user
    return None


def admin_action():
    if current_user and current_user["role"] == "admin":
        return "Admin role detected and admin action performed."
    return "Access denied. This action is restricted to administrators."


def user_action():
    if current_user and current_user["role"] == "user":
        return "User action performed."
    return "Access denied. This action is restricted to regular users."


def user_test(user):
    print("Testing login functionality for user:", user)
    try:
        current_user = login(user)
        print(
            current_user["username"],
            "logged in as",
            roles[current_user["role"]]["name"],
        )
    except Exception as e:
        print("Login failed:", e)
    else:
        print("Now performing an admin action:")
        print(admin_action())
        print("Now testing a regular user action:")
        print(user_action())


header_char = "═"
current_user = None

print("\n" + header_char * 60)
username = "student1"
print("\nRegular user test:\n\n")
user_test(username)


print("\n" + header_char * 60)
print("\nAdmin user test:\n\n")
username = "instructor1"
user_test(username)

"""

This application demonstrates the principle of Confidentiality from the CIA triad
by restricting access to sensitive actions based on user roles. 

Admin users can perform all actions, while regular users have limited access.

Authentication is demonstrated through the login function, which verifies user
credentials. Authorization is handled through role-based access control.

"""
