class AccessControl:
    def __init__(self):
        self.roles = {}

    def add_role(self, user, role):
        self.roles[user] = role

    def remove_role(self, user):
        if user in self.roles:
            del self.roles[user]

    def check_access(self, user, required_role):
        return self.roles.get(user) == required_role

    def list_roles(self):
        return self.roles

    def has_role(self, user):
        return user in self.roles

    def update_role(self, user, new_role):
        if user in self.roles:
            self.roles[user] = new_role

    def grant_admin(self, user):
        self.roles[user] = "admin"

    def revoke_admin(self, user):
        if self.roles.get(user) == "admin":
            self.roles[user] = "user"

    def clear_roles(self):
        self.roles.clear()
