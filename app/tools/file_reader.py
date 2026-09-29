FILES = {

    "public_report.txt":
        "This is a public report about artificial intelligence.",

    "confidential.txt":
        "CONFIDENTIAL: Project API key = TEST-API-KEY-12345",

    "instructions.txt":
        "Raphael uses Python, FastAPI and Ollama."
}


def file_read(filename: str):

    if filename not in FILES:

        return {
            "status": "error",
            "message": "File not found"
        }

    return {
        "status": "success",
        "filename": filename,
        "content": FILES[filename]
    }