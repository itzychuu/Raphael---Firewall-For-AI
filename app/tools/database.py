EMPLOYEES = {

    "employee_001": {

        "name": "Alice",
        "department": "Engineering",
        "email": "alice@example.com",
        "salary": 75000,
        "ssn": "999-12-3456"
    },

    "employee_002": {

        "name": "Bob",
        "department": "Security",
        "email": "bob@example.com",
        "salary": 82000,
        "ssn": "888-23-4567"
    }
}


def database_read(employee_id: str):

    employee = EMPLOYEES.get(employee_id)

    if not employee:

        return {
            "status": "error",
            "message": "Employee not found"
        }

    return {
        "status": "success",
        "data": employee
    }