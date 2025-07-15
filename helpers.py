# helpers.py
from textwrap import dedent
from typing import List
from crewai import Agent, Task, LLM
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from exa_py import Exa
from crewai.tools import tool
import os

class ExaSearchTool:
    """Tools for searching the web using Exa AI."""
    @tool
    def search(query: str):
        """Search for a webpage based on the query."""
        return ExaSearchTool._exa().search(f"{query}", use_autoprompt=True, num_results=3)

    @tool
    def search_and_contents(url:str):
        """
        Get the searches and contents of a given url
        """
        return ExaSearchTool._exa().search_and_contents(url, num_results=3)

    @tool
    def get_contents(urls: List[str]):
        """Get the contents of a webpage.
        The urls must be passed in as a list, a list of urls returned from `search`.
        """
        # ids = eval(ids) # Safely evaluate the string representation of a list
        contents = str(ExaSearchTool._exa().get_contents(urls))
        contents = contents.split("URL:")
        contents = [content[:1000] for content in contents] # Limit content length
        return "\n\n".join(contents)

    def tools():
        return [ExaSearchTool.search, ExaSearchTool.search_and_contents, ExaSearchTool.get_contents]

    def _exa():
        # Ensure EXA_API_KEY is set in the environment or loaded via dotenv
        return Exa(api_key=os.environ.get("EXA_API_KEY"))

class SecurityAnalysisAgents:
    """Defines the AI agents for security analysis."""
    def __init__(self, openai_api_key):
        self.llama3 = ChatNVIDIA( 
            model="nvidia/llama-3.3-nemotron-super-49b-v1",
            api_key=openai_api_key,
            )

    def industry_analysis_agent(self):
        return Agent(
            role='Industry Analyst',
            goal='Analyze the current industry measures, security protocols that are standard in that industry',
            tools=ExaSearchTool.tools(),
            llm=self.llama3,
            backstory=dedent("""\
                As an Industry Analyst for security purposes, your analysis will identify key security trends and security protocols in the industry."""),
            verbose=True
        )

    def frontend_security_agent(self):
        return Agent(
            role='Frontend security Analyst',
            goal='Check for security breaches on the front end of the website and describe them in great detail',
            tools=ExaSearchTool.tools(),
            llm=self.llama3,
            backstory=dedent("""\
                You are responsible for assessing the website's front-end security, focusing on preventing and mitigating injection attacks such as SQL injection and cross-site scripting (XSS). Conduct thorough checks across these key areas:"""),
            verbose=True
        )

    def network_security_agent(self, url): # Pass url to agent backstory
        return Agent(
            role='Network security Analyst',
            goal='Check for security breaches on the network communication of a website and describe them in great detail',
            tools=ExaSearchTool.tools(),
            llm=self.llama3,
            backstory=dedent(f"""\
                You are tasked with evaluating the network security measures of the website {url}. Your focus is on ensuring robust security practices are in place for data transmission, access control, session management, and overall network integrity. Follow these detailed checks"""),
            verbose=True
        )

    def summary_and_briefing_agent(self):
        return Agent(
            role='Briefing Coordinator',
            goal='Compile all gathered information into a concise, informative briefing document',
            tools=ExaSearchTool.tools(),
            llm=self.llama3,
            backstory=dedent("""\
                As the Briefing Coordinator, your role is to consolidate the research,
                analysis, and actionable steps to remove the security weaknesses of the website."""),
            verbose=True
        )

class SecurityAnalysisTasks:
    """Defines the tasks for the security analysis agents."""
    def research_task(self, agent, url):
        return Task(
            description=dedent(f"""\
                Research the website {url} to gather initial information about its general purpose and any publicly available information related to its industry's security measures.
                website : {url}"""), # Keep this for general context if the agent needs it.
            expected_output=dedent("""\
                A detailed report summarizing key findings about the website's industry, relevant security measures, and security protocols to be strictly followed.
                The report should primarily be based on the content retrieved directly from the website {url}."""),
            async_execution=True,
            agent=agent
        )

    def frontend_analysis_task(self, agent, url, context):
        return Task(
            description=dedent(f"""\
                {context}
                Input Validation and Sanitization
                > Validate user inputs against expected formats.
                > Sanitize inputs to neutralize malicious code.
                > Escape user data in HTML, JS, CSS to prevent injection.

                Content Security Policy (CSP)
                > Implement a CSP to restrict script sources.
                > Configure CSP to allow only trusted sources.

                Cross-Site Scripting (XSS)
                > Inspect user input/output for XSS vulnerabilities.
                > Use frameworks with strong XSS protection.

                Cross-Site Request Forgery (CSRF)
                > Use unique anti-CSRF tokens for forms and requests.
                > Validate tokens on the server side.

                Security Headers for Front-End
                > Confirm X-XSS-Protection header presence.
                > Check for X-Content-Type-Options header.

                Secure Coding Practices
                > Adhere to secure coding standards, avoid risky functions.
                > Use third-party scripts from trusted sources.

                Client-Side Encryption
                > Encrypt sensitive client-side data in local storage/cookies.
                > Use strong, accepted encryption algorithms.

                Form Security
                > Validate and sanitize form inputs client and server side.
                > Include CAPTCHA for form submissions.

                Error Handling
                > Prevent error messages from exposing sensitive info.
                > Log detailed errors securely, show generic messages to users.

                JavaScript Security
                > Avoid injecting/executing harmful JavaScript.
                > Enforce CSP to restrict inline/untrusted scripts.

                File Upload Security
                > Restrict uploads to safe types/sizes with validation.
                > Securely store and scan uploads for malware.

                Dynamic Content Security
                > Securely handle dynamic content to prevent injection.
                > Use templating engines for XSS and injection protection.

                Third-Party Script Management
                > Manage and review third-party scripts for security risks.

                {url}/robots.txt route should not exist and explain the possible security breach because of its existence
                {url}/.well-known/security.txt  route should exist and explain the need for its existence in the website.
                Also explain actionable plans to implement them

                website : {url}"""),
            expected_output=dedent("""\
                A detailed report on frontend vulnerabilities, including specific findings related to input validation, CSP, XSS, CSRF, security headers, secure coding practices, client-side encryption, form security, error handling, JavaScript security, file upload security, dynamic content security, and third-party script management. It should also address the presence/absence of robots.txt and security.txt with actionable plans for implementation where necessary."""),
            async_execution=False,
            agent=agent
        )

    def network_analysis_task(self, agent, url, context):
        return Task(
            description=dedent(f"""\
                {context}

                Please perform the following in the code given above
                ### Authentication and Authorization
                - Implement multi-factor authentication (MFA) for user logins.
                - Secure endpoints to prevent unauthorized access.
                - Implement account locking after failed login attempts.

                ### Data Encryption
                - Enforce HTTPS for secure data transmission.
                - Encrypt sensitive information during transmission and at rest.
                - Maintain up-to-date and valid TLS certificates.

                ### Session Management
                - Use HttpOnly and Secure flags for session cookies.
                - Set appropriate session timeout periods.
                - Use complex, randomly generated session IDs.

                ### Security Headers
                - Implement essential security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection.
                - Enforce Strict-Transport-Security (HSTS) header.

                ### Access Control
                - Review and configure roles and permissions correctly.
                - Restrict access to sensitive areas, like admin panels.

                ### Vulnerability Management
                - Conduct regular vulnerability scanning and patching.
                - Keep third-party libraries and dependencies updated.

                ### Logging and Monitoring
                - Log security events and activities securely.
                - Regularly monitor logs for suspicious activity.

                ### API Security
                - Secure APIs with appropriate authentication and authorization.
                - Encrypt data transmitted via APIs.
                - Implement rate limiting and monitoring for API endpoints.

                ### Backup and Recovery
                - Maintain a robust backup and disaster recovery plan.
                - Encrypt and securely store backups.

                ### Compliance
                - Ensure compliance with relevant standards and regulations.
                website = {url}"""),
            expected_output=dedent("""\
                A comprehensive report on network vulnerabilities, covering authentication, authorization, data encryption, session management, security headers, access control, vulnerability management, logging, API security, backup and recovery, and compliance. The report should detail any identified flaws and provide actionable steps to address them."""),
            async_execution=False,
            agent=agent
        )

    def summary_and_briefing_task(self, agent):
        return Task(
            description=dedent(f"""\
                Compile all the research findings, industry analysis, and strategic
                action points into a detailed report, comprehensive briefing document for
                the overview.
                Ensure the briefing lists *ONLY THE VULNERABILITIES FOUND* and none else.

        """),
            expected_output=dedent("""\
                A well-structured briefing document that includes all the vulnerabilities in the following format
                Vulnerability Report: ___ Website

                Introduction
                _____

                Vulnerabilities Found
                1.
                2.
                3.
                4.
                ..

                Steps to solve the vulnerabilities
                1.
                2.
                3.
                4.
                ...

                In conclusion
                _____

                Note:
                _____"""),
            async_execution=False,
            agent=agent
        )