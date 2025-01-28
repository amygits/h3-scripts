import os
import requests
import json
import csv
from dotenv import load_dotenv

load_dotenv()

API_TOKEN = os.getenv("API_TOKEN")
H3_GRAPHQL_URL = os.getenv("H3_GRAPHQL_URL")
H3_AUTH_URL = os.getenv("H3_AUTH_URL")


# Obtains a H3 Access token using the generated API secret
def _obtain_access_token() -> str:
    if not API_TOKEN:
        raise Exception("A valid token is required")
    response = requests.post(
        H3_AUTH_URL,
        headers={"Content-Type": "application/json"},
        json={"key": API_TOKEN},
    )
    response.raise_for_status()
    return (
        response.json().get("token")
        if response.status_code == 200
        else Exception("An error occurred while retrieving a token")
    )

def submit_query(query: str, variables: dict) -> dict:
    
    if variables is None:
        variables = {}
        
    auth_header = f"Bearer {_obtain_access_token()}"
    
    response = requests.post(
        url=H3_GRAPHQL_URL,
        headers={"Authorization": auth_header},
        json={"query": query, "variables": variables},
    )
    
    result = (
        response.json()
        if response.status_code == 200
        else Exception("An error occurred while making the request")
    )
    
    return result

# Executes query that returns the most recent 10 ops
def pull_10_ops() -> dict:

    query = """
        query op_tabs_page(
            $page_input: PageInput,
            $exclude_sample_ops: Boolean
        ) {
            op_tabs_page(
                page_input: $page_input,
                exclude_sample_ops: $exclude_sample_ops
            ) {
                op_tabs {
                    ...OpTabFragment
                }
            }
        }

        fragment OpTabFragment on OpTab {
            op_id
        }
        """

    variables = {
        "page_input": {"page_num": 1, "page_size": 10},
        "exclude_sample_ops": True,
    }

    result = submit_query(query, variables)
    return result


def get_op_info(op_id: str) -> dict:

    variables = {"op_id": op_id}
    query = """
    query pentest($op_id: String!) {
        pentest(op_id: $op_id) {
            op_id
            name
            client_name
            weakness_types_count
            weaknesses_count
            weaknesses_page {
                ...WeaknessesPageFragment
            }
        }
    }

    fragment WeaknessesPageFragment on WeaknessesPage {
        weaknesses {
            created_at
            uuid
            vuln_id
            vuln_category
            vuln_name
            ip
            score
            severity
            base_score
            base_severity
            context_score
            context_severity
        }
    }
    """    
    result = submit_query(query, variables)
    return result


def print_to_csv(op_details: dict):
    filepath = "./weaknesses.csv"
    headers = [
        "op_id",
        "pentest_name",
        "client_name",
        "weakness_count",
        "vuln_id",
        "vuln_name",
        "vuln_category",
        "affected_ip",
        "score",
        "severity",
        "base_score",
    ]

    if not os.path.exists(filepath):
        with open(filepath, "w", newline="") as csvfile:

            writer = csv.writer(
                csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
            )
            writer.writerow(headers)
    op_id = op_details.get("data").get("pentest").get("op_id")
    pentest_name = op_details.get("data").get("pentest").get("name")
    client_name = op_details.get("data").get("pentest").get("client_name")
    weaknesses = op_details.get("data").get("pentest").get("weaknesses_page").get("weaknesses")
    if len(weaknesses) == 0:
        with open(filepath, 'a') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                op_id, 
                pentest_name, 
                client_name, 
                0
                ])
    else:
        with open(filepath, "a") as csvfile:
            writer = csv.writer(csvfile)
            for weakness in weaknesses:
                writer.writerow([
                    op_id,
                    pentest_name,
                    client_name,
                    len(weaknesses),
                    weakness.get("vuln_id"),
                    weakness.get("vuln_name"),
                    weakness.get("vuln_category"),
                    weakness.get("ip"),
                    weakness.get("score"),
                    weakness.get("severity"),
                    weakness.get("base_score"),
                ]
                )


def main():
    ops_list = pull_10_ops()
    op_ids = ops_list.get("data").get("op_tabs_page").get("op_tabs")
    for id in op_ids:
        print_to_csv(get_op_info(id.get("op_id")))


if __name__ == "__main__":
    main()
