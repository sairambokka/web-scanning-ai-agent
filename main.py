# main.py
import os
from crewai import Crew
from bs4 import BeautifulSoup

# Import functions and classes from helpers.py and utils.py
from helpers import SecurityAnalysisAgents, SecurityAnalysisTasks, ExaSearchTool
from utils import get_api_keys, get_network_and_dom_data, analyze_network_data, analyze_security_flaws

def run_security_analysis():
    print("## Welcome to the Website Security Analysis Crew")

    # Get URL input
    url = input("Enter Your URL : ")

    # Get API keys
    openai_api_key, exa_api_key = get_api_keys()

    # Set environment variables for CrewAI tools
    os.environ["OPENAI_API_KEY"] = openai_api_key
    os.environ["EXA_API_KEY"] = exa_api_key

    # Get Network Logs and DOM data
    print("Getting Network Logs + DOM data...")
    src, network_list = get_network_and_dom_data(url)
    print("Data extraction complete.")

    # Analyze network data
    total_network_analysis = analyze_network_data(network_list)
    network_issues = analyze_security_flaws(network_list)

    # Prepare contexts for agents
    Network_context = f'''\n\n Network Logs + potential flaws:\nObservations : {total_network_analysis['resource_counts']}\nFlaws : {network_issues}'''

    # Extracting vulnerable tags from source code
    soup = BeautifulSoup(src, 'html.parser')
    scripts = soup.find_all('script')
    Code_context = f'''\n Source Code :\nscripts : {str(scripts)}'''


    # Initialize Agents and Tasks
    agents = SecurityAnalysisAgents(openai_api_key=openai_api_key)
    tasks = SecurityAnalysisTasks()


    industry_analyst_agent = agents.industry_analysis_agent()
    frontend_security_agent = agents.frontend_security_agent()
    network_security_agent = agents.network_security_agent(url) # Pass URL to network agent
    summary_and_briefing_agent = agents.summary_and_briefing_agent()

    industry_analysis_task = tasks.research_task(industry_analyst_agent, url)
    frontend_research_task = tasks.frontend_analysis_task(frontend_security_agent, url, Code_context)
    network_research_task = tasks.network_analysis_task(network_security_agent, url, Network_context)
    summary_and_briefing_task = tasks.summary_and_briefing_task(summary_and_briefing_agent)

    # Set task contexts
    frontend_research_task.context = [industry_analysis_task]
    network_research_task.context = [industry_analysis_task]
    summary_and_briefing_task.context = [frontend_research_task, network_research_task, industry_analysis_task]

    # Create and kickoff the Crew
    crew = Crew(
        agents=[
            industry_analyst_agent,
            frontend_security_agent,
            network_security_agent,
            summary_and_briefing_agent
        ],
        tasks=[
            industry_analysis_task,
            frontend_research_task,
            network_research_task,
            summary_and_briefing_task
        ],
        verbose=True,
    )

    result = crew.kickoff()
    print("\n\n################################################")
    print(result.raw)

if __name__ == "__main__":
    run_security_analysis()