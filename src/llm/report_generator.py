
from urllib import response
from xmlrpc import client

import google.generativeai as genai
from openai import OpenAI

def create_incident_report(subset_df):
   # Assume anamoly_df already has explanation and risk_level columns
    
    # Build the incident summary prompt
    report_sections = []
    for i, row in subset_df.iterrows():
        #print(">>>>>>>>>", row)
        user = row['username_x']
        role = row['department']
        risk = row['risk_score']
        risk_level = row['risk_level']
        flags = row['explanation']

        section = f"""
            Alert {i+1}:
            User: {user} ({role})
            Risk Score: {risk}/100  {risk_level}

            Flags:
                - {flags}

            Recommendation: Explain why this is suspicious. Provide recommendation.
        """
        report_sections.append(section)

        # Combine into one single prompt
    incident_report_prompt = f"""
    You are a cybersecurity analyst generating incident summary reports. Explain why each alert is suspicious and provide recommendation for each alert
    DATA ACCESS ANOMALY REPORT - CONTEXT

    {''.join(report_sections)}
    """

    genai.configure(api_key="YOUR_GOOGLE_API_KEY")

    # Choose a Gemini model (text generation)
    model = genai.GenerativeModel("gemini-2.5-flash")

    response = model.generate_content(incident_report_prompt)

    print(response.text)

    # Save to file
    with open(r"output/incident_summary_gemini.txt", "w", encoding="utf-8") as f:
        f.write(response.text)


    

