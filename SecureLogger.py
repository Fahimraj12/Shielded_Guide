class SecureLogger:
    def __init__(self, log_file="security.log"):
        self.logger = logging.getLogger("ShieldedGuide")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        self.logger.addHandler(handler)

    def log(self, message):
        self.logger.info(message)

    def log_warning(self, message):
        self.logger.warning(message)

    def log_error(self, message):
        self.logger.error(message)

    def log_critical(self, message):
        self.logger.critical(message)

    def log_access(self, user, action):
        self.logger.info(f"{user} performed {action}")

    def log_failed_attempt(self, user):
        self.logger.warning(f"Failed attempt by {user}")

    def log_successful_login(self, user):
        self.logger.info(f"{user} logged in successfully")

    def log_admin_action(self, admin, action):
        self.logger.info(f"Admin {admin} executed {action}")

    def log_encryption_action(self, action):
        self.logger.info(f"Encryption action: {action}")

    def log_security_breach(self, user):
        self.logger.critical(f"Security breach detected for user {user}")
