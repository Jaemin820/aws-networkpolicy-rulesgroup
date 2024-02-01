import boto3
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

def get_ip_list(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return list(set(response.json())), url.split('/')[4] + '-rule-group'
    except requests.RequestException as e:
        logging.error(f"Error retrieving data from {url}: {e}")
        return [], None

def manage_rule_group(client, rule_group_name, ips, capacity=100):
    try:
        client.describe_rule_group(RuleGroupName=rule_group_name, Type='STATELESS')
        update_rule_group(client, rule_group_name, ips)
    except client.exceptions.ResourceNotFoundException:
        create_rule_group(client, rule_group_name, ips, capacity)

def create_rule_group(client, rule_group_name, ips, capacity):
    stateless_rules = {
            'StatelessRules': [
                {
                    'RuleDefinition': {
                        'MatchAttributes': {
                            'Destinations': [{'AddressDefinition': ip + '/32'} for ip in ips]
                        },
                        'Actions': ['aws:pass']
                    },
                    'Priority': 1
                }
            ],
            'CustomActions': []
        }

    try:
        response = client.create_rule_group(
            RuleGroupName=rule_group_name,
            RuleGroup={'RulesSource': {'StatelessRulesAndCustomActions': stateless_rules}},
            Type='STATELESS',
            Capacity=capacity
        )
        logging.info(f"Rule group created: {rule_group_name}")
        return response
    except client.exceptions.InvalidRequestException:
        logging.error(f"Rule group already exists: {rule_group_name}")
        update_rule_group(client, rule_group_name, ips)
    except Exception as e:
        logging.error(f"Error creating rule group {rule_group_name}: {e}")

def update_rule_group(client, rule_group_name, ips):
    try: 
        # 기존 규칙 그룹의 설정을 가져옵니다.
        rule_group = client.describe_rule_group(
            RuleGroupName=rule_group_name,
            Type='STATELESS'
        )

        # 기존 규칙 그룹의 설정을 업데이트합니다.
        rule_group['RuleGroup']['RulesSource']['StatelessRulesAndCustomActions']['StatelessRules'][0]['RuleDefinition']['MatchAttributes']['Destinations'] = [
            {'AddressDefinition': ip + '/32'} for ip in ips
        ]

        # 업데이트된 규칙 그룹을 AWS에 적용합니다.
        client.update_rule_group(
            UpdateToken=rule_group['UpdateToken'],
            RuleGroupName=rule_group_name,
            RuleGroup=rule_group['RuleGroup'],
            Type='STATELESS'
        )
        logging.info(f"Rule group updated: {rule_group_name}")
    except Exception as e:
        logging.error(f"Error updating rule group {rule_group_name}: {e}")

def main():
    # URLs and AWS client initialization
    # List of source IPs URLs
    white_list_url = [
        "https://grafana.com/api/hosted-grafana/source-ips",
        "https://grafana.com/api/hosted-alerts/source-ips",
        "https://grafana.com/api/hosted-metrics/source-ips",
        "https://grafana.com/api/hosted-traces/source-ips",
        "https://grafana.com/api/hosted-logs/source-ips",
        "https://grafana.com/api/hosted-profiles/source-ips"
    ]

    # AWS Network Firewall client initialization
    client = boto3.client('network-firewall', region_name='ap-northeast-2')

    for url in white_list_url:
        ip_list, group_name = get_ip_list(url)
        if not ip_list or not group_name:
            continue
        if len(ip_list) > 100:
            for i in range(0, len(ip_list), 100):
                manage_rule_group(client, f"{group_name}-{i//100}", ip_list[i:i+100])
        else:
            manage_rule_group(client, group_name, ip_list)

if __name__ == "__main__":
    main()
