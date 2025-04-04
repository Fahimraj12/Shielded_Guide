class DataSanitizer:
    def sanitize_sql(self, input_string):
        return input_string.replace("'", "''")  

    def sanitize_xss(self, input_string):
        return input_string.replace("<", "&lt;").replace(">", "&gt;")

    def sanitize_url(self, url):
        return re.sub(r"[^\w:/?=&]", "", url)

    def remove_html_tags(self, input_string):
        return re.sub(r"<.*?>", "", input_string)

    def sanitize_email(self, email):
        return re.sub(r"[^\w@.]", "", email)

    def sanitize_phone_number(self, phone):
        return re.sub(r"[^\d]", "", phone)

    def sanitize_username(self, username):
        return re.sub(r"[^\w]", "", username)

    def prevent_script_injection(self, input_string):
        return re.sub(r"(<script.*?>.*?</script>)", "", input_string, flags=re.DOTALL)

    def sanitize_json(self, json_string):
        return re.sub(r"[^\w{}:,\[\]\" ]", "", json_string)

    def validate_safe_input(self, input_string):
        return bool(re.match(r"^[\w\s\.\-\@]+$", input_string))
