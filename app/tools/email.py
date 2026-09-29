def send_email(recipient: str, message: str):

    return {

        "status": "success",

        "action": "email_sent",

        "recipient": recipient,

        "message": message
    }