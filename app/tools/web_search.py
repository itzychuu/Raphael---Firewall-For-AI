def web_search(query: str):

    knowledge = {

        "python":
            "Python is a high-level programming language.",

        "fastapi":
            "FastAPI is a Python framework for building APIs.",

        "llm":
            "An LLM is a large language model.",

        "phishing":
            "Phishing is a social engineering attack."
    }

    query_lower = query.lower()

    for keyword, result in knowledge.items():

        if keyword in query_lower:

            return {
                "status": "success",
                "query": query,
                "result": result
            }

    return {
        "status": "success",
        "query": query,
        "result": "No matching information found."
    }