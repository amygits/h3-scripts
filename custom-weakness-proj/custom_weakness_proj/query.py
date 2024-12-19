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
    return response.json().get("token") if response.status_code == 200 else None


# Executes query that returns the most recent 10 ops
def pull_10_ops() -> dict:

    access_token = _obtain_access_token()
    graphql_query = """
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

    auth_header = f"Bearer {access_token}"

    response = requests.post(
        url=H3_GRAPHQL_URL,
        headers={"Authorization": auth_header},
        json={"query": graphql_query, "variables": variables},
    )
    result = response.json() if response.status_code == 200 else None
    return result


# Iterates through list of op_ids and prints each op's weakness data to custom csv
def print_weaknesses(op_ids: list):

    access_token = _obtain_access_token()
    auth_header = f"Bearer {access_token}"
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
    op_headers = ["op_id", "name", "client_name", "weaknesses_count"]
    weakness_headers = [
        " ",
        "vuln_id",
        "vuln_name",
        "vuln_category",
        "ip",
        "score",
        "severity",
        "base_score",
    ]
    delimiter = "X" * len(weakness_headers)

    with open("last-10-op-weaknesses.csv", "w", newline="") as csvfile:

        writer = csv.writer(
            csvfile, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL
        )

        for id in op_ids:
            op_id = id.get("op_id")
            variables = {"op_id": op_id}
            response = requests.post(
                url=H3_GRAPHQL_URL,
                headers={"Authorization": auth_header},
                json={"query": query, "variables": variables},
            )
            result = response.json() if response.status_code == 200 else None
            writer.writerow(op_headers)
            writer.writerow(
                [
                    result.get("data").get("pentest").get("op_id"),
                    result.get("data").get("pentest").get("name"),
                    result.get("data").get("pentest").get("client_name"),
                    result.get("data").get("pentest").get("weaknesses_count"),
                ]
            )

            weaknesses = (
                result.get("data")
                .get("pentest")
                .get("weaknesses_page")
                .get("weaknesses")
            )
            writer.writerow(weakness_headers)
            for weakness in weaknesses:
                writer.writerow(
                    [
                        "#",
                        weakness.get("vuln_id"),
                        weakness.get("vuln_name"),
                        weakness.get("vuln_category"),
                        weakness.get("ip"),
                        weakness.get("score"),
                        weakness.get("severity"),
                        weakness.get("base_score"),
                    ]
                )
            writer.writerow(delimiter)


def main():
    ops_list = pull_10_ops()
    op_ids = ops_list.get("data").get("op_tabs_page").get("op_tabs")
    print_weaknesses(op_ids)


if __name__ == "__main__":
    main()
