import snyk
import pandas as pd
import datetime

# Snyk API token
SNYK_API_TOKEN = "1b6bb545-8032-4515-9408-683c6dcb0275"
EXCLUDE_ORG = "Aerospike Sandboxes"  # Organization to exclude
EXCLUDE_PROJECT = "trusleaf/ecosystem-automation"  # Project to exclude

snyk_client = snyk.SnykClient(SNYK_API_TOKEN)

# Initialize list to store project data
projects_data = []

print("Generating Snyk vulnerability report. Please wait...")

# Severity rank mapping
SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}

try:
    # Fetch all organizations
    organizations = snyk_client.organizations.all()

    # Filter out the excluded organization
    target_organizations = [org for org in organizations if org.name != EXCLUDE_ORG]

    for org in target_organizations:
        # Fetch all projects in the organization
        projects = org.projects.all()

        for project in projects:
            if project.name == EXCLUDE_PROJECT:
                continue  # Skip the excluded project

            try:
                # Fetch aggregated issues for the project
                issues_aggregated = project.issueset_aggregated.all()

                if not hasattr(issues_aggregated, "issues") or not issues_aggregated.issues:
                    continue

                for issue in issues_aggregated.issues:
                    # Only include fixable issues
                    if issue.fixInfo and issue.fixInfo.isFixable:
                        severity = issue.issueData.severity.lower() if issue.issueData and issue.issueData.severity else "unknown"
                        issue_data = {
                            "ISSUE_SEVERITY_RANK": SEVERITY_RANK.get(severity, 0),  # Map severity to rank
                            "ISSUE_SEVERITY": severity.capitalize() if severity != "unknown" else "Unknown",
                            "SCORE": issue.priority["score"] if hasattr(issue, "priority") else "Unknown",
                            "PROBLEM_TITLE": issue.issueData.title if issue.issueData else "Unknown",
                            "CVE": ", ".join(issue.issueData.identifiers.get("CVE", [])) if issue.issueData and hasattr(issue.issueData, "identifiers") else "No CVE Found",
                            "CVE_URL": ", ".join([f"https://www.cve.org/CVERecord?id={cve}" for cve in issue.issueData.identifiers.get("CVE", [])]) if issue.issueData and hasattr(issue.issueData, "identifiers") else "Not Available",
                            "CWE": ", ".join(issue.issueData.identifiers.get("CWE", [])) if issue.issueData and hasattr(issue.issueData, "identifiers") else "No CWE Found",
                            "PROJECT_NAME": project.name,
                            "PROJECT_URL": project.url if hasattr(project, "url") else "URL not available",
                            "EXPLOIT_MATURITY": issue.issueData.exploitMaturity if issue.issueData and hasattr(issue.issueData, "exploitMaturity") else "No data",
                            "AUTOFIXABLE": "Fixable" if issue.fixInfo.isFixable else "Not Fixable",
                            "FIRST_INTRODUCED": issue.issueData.publicationTime if issue.issueData and hasattr(issue.issueData, "publicationTime") else "Unknown",
                            "PRODUCT_NAME": project.origin if hasattr(project, "origin") else "Unknown Product",
                            "ISSUE_URL": issue.issueData.url if issue.issueData and hasattr(issue.issueData, "url") else "Not Available",
                            "ISSUE_STATUS_INDICATOR": issue.issueData.status if issue.issueData and hasattr(issue.issueData, "status") else "Open",
                            "ISSUE_TYPE": issue.issueType if hasattr(issue, "issueType") else "Unknown",
                        }
                        projects_data.append(issue_data)
            except Exception as e:
                continue

except Exception as e:
    print(f"An error occurred: {e}")
    exit()

# Convert data to a Pandas DataFrame
df = pd.DataFrame(projects_data)

# Reorder columns
column_order = [
    "ISSUE_SEVERITY_RANK", "ISSUE_SEVERITY", "SCORE", "PROBLEM_TITLE", "CVE", 
    "CVE_URL", "CWE", "PROJECT_NAME", "PROJECT_URL", "EXPLOIT_MATURITY", 
    "AUTOFIXABLE", "FIRST_INTRODUCED", "PRODUCT_NAME", "ISSUE_URL", 
    "ISSUE_STATUS_INDICATOR", "ISSUE_TYPE"
]
df = df[column_order]

# Add timestamp to filename for versioning
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
filename_base = f"snyk_fixable_issues_{timestamp}"
filename_sorted = f"snyk_fixable_issues_sorted_{timestamp}.csv"

# Save the first report
if not df.empty:
    df.to_csv(f"{filename_base}.csv", index=False)

    # Create a sorted version of the DataFrame
    df_sorted = df.sort_values(by=["ISSUE_SEVERITY_RANK", "SCORE"], ascending=[False, False])
    
    # Save the sorted DataFrame
    df_sorted.to_csv(filename_sorted, index=False)
    print(f"Reports generated successfully:\n1. {filename_base}.csv\n2. {filename_sorted}")
else:
    print("No fixable issues found across the target organizations.")
