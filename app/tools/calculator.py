def calculator(expression: str):

    try:

        allowed = "0123456789+-*/(). "

        if not all(char in allowed for char in expression):

            return {
                "status": "error",
                "message": "Invalid mathematical expression"
            }

        result = eval(
            expression,
            {"__builtins__": {}},
            {}
        )

        return {
            "status": "success",
            "result": result
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }