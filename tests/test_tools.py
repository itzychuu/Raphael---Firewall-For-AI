from app.tools.calculator import calculator
from app.tools.web_search import web_search
from app.tools.database import database_read
from app.tools.file_reader import file_read
from app.tools.email import send_email


def test_calculator():

    result = calculator("25 * 40")

    assert result["result"] == 1000


def test_web_search():

    result = web_search("What is Python?")

    assert result["status"] == "success"


def test_database():

    result = database_read("employee_001")

    assert result["status"] == "success"


def test_file_reader():

    result = file_read("public_report.txt")

    assert result["status"] == "success"


def test_email():

    result = send_email(
        "test@example.com",
        "Hello"
    )

    assert result["status"] == "success"