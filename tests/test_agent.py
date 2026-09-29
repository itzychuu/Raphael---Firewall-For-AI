from app.agent.agent import run_agent


def test_agent():

    result = run_agent(
        "Explain what an AI agent is in one sentence."
    )

    assert result["response"]

    print("\nAgent response:")
    print(result["response"])