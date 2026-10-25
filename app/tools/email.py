def send_email(recipient: str, message: str, subject: str = "Notification"):
    """Simulated outbound email dispatcher for safe sandbox execution."""
    return {
        "status": "success",
        "action": "email_sent",
        "simulated": True,
        "recipient": recipient,
        "subject": subject,
        "message": message,
    }