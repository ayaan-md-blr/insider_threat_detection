def create_incident_report(
    user,
    role,
    risk,
    flags
):
    prompt = f"""

    User: {user}

    Role: {role}

    Risk Score: {risk}

    Flags:
    {flags}

    Explain why this is suspicious.
    Provide recommendation.
    """