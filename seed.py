#!/usr/bin/env python3
import os
import sys
from dotenv import load_dotenv
from neo4j import GraphDatabase

# Load environment variables
load_dotenv()

def seed_database():
    uri = os.getenv("COGNODB_URI")
    user = os.getenv("COGNODB_USER", "cognodb")
    password = os.getenv("COGNODB_PASSWORD")

    if not uri or not password:
        print("Error: COGNODB_URI and COGNODB_PASSWORD must be set in your environment or .env file.")
        sys.exit(1)

    print(f"Connecting to CognoDB at {uri}...")
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        # Test connection
        driver.verify_connectivity()
    except Exception as e:
        print(f"Error: Failed to connect to CognoDB: {e}")
        print("Please check your URI and credentials.")
        sys.exit(1)

    print("Successfully connected. Cleaning up existing database...")
    
    # Define creation statements
    queries = [
        # 1. Clear database
        "MATCH (n) DETACH DELETE n",
        
        # 2. Create User nodes
        """
        CREATE (alice:User:Asset {id: 'u-alice', name: 'Alice Smith', type: 'User', role_title: 'Lead Cloud Architect', status: 'Active', criticality: 'High'})
        CREATE (bob:User:Asset {id: 'u-bob', name: 'Bob Johnson', type: 'User', role_title: 'Junior Developer', status: 'Active', criticality: 'Low'})
        CREATE (charlie:User:Asset {id: 'u-charlie', name: 'Charlie Brown', type: 'User', role_title: 'SecOps Analyst', status: 'Active', criticality: 'Medium'})
        CREATE (david:User:Asset {id: 'u-david', name: 'David Miller', type: 'User', role_title: 'Marketing Specialist', status: 'Active', criticality: 'Low'})
        CREATE (eve:User:Asset {id: 'u-eve', name: 'Eve Malloy', type: 'User', role_title: 'External Contractor', status: 'Suspended', criticality: 'Low'})
        """,
        
        # 3. Create Group nodes
        """
        CREATE (gdevs:Group:Asset {id: 'g-devs', name: 'DevOps Engineering Group', type: 'Group', criticality: 'Medium'})
        CREATE (gsec:Group:Asset {id: 'g-security', name: 'Security Administrator Group', type: 'Group', criticality: 'High'})
        CREATE (gmkt:Group:Asset {id: 'g-marketing', name: 'Marketing & Ops Group', type: 'Group', criticality: 'Low'})
        """,
        
        # 4. Create IAM Role nodes
        """
        CREATE (radmin:Role:Asset {id: 'r-admin-role', name: 'AWSAdministratorAccess', type: 'Role', arn: 'arn:aws:iam::123456789012:role/AdministratorAccess', criticality: 'High'})
        CREATE (rdb:Role:Asset {id: 'r-db-reader', name: 'RDSReadOnlyAccess', type: 'Role', arn: 'arn:aws:iam::123456789012:role/RDSReadOnlyAccess', criticality: 'Medium'})
        CREATE (rweb:Role:Asset {id: 'r-web-app', name: 'WebAppEC2InstanceProfile', type: 'Role', arn: 'arn:aws:iam::123456789012:role/WebAppInstanceProfile', criticality: 'Medium'})
        CREATE (rsec:Role:Asset {id: 'r-security-auditor', name: 'SecurityAuditRole', type: 'Role', arn: 'arn:aws:iam::123456789012:role/SecurityAudit', criticality: 'High'})
        """,
        
        # 5. Create Compute nodes (EC2/Servers)
        """
        CREATE (cprodweb:Compute:Asset {id: 'c-prod-web', name: 'prod-web-server-01', type: 'Compute', ip_address: '54.210.15.22', public: true, status: 'Running', criticality: 'High'})
        CREATE (cdevbastion:Compute:Asset {id: 'c-dev-bastion', name: 'dev-bastion-host', type: 'Compute', ip_address: '34.220.89.10', public: true, status: 'Running', criticality: 'Medium'})
        CREATE (cinternalapi:Compute:Asset {id: 'c-internal-api', name: 'internal-api-server', type: 'Compute', ip_address: '10.0.2.15', public: false, status: 'Running', criticality: 'Medium'})
        CREATE (cmktsite:Compute:Asset {id: 'c-marketing-site', name: 'marketing-public-wp', type: 'Compute', ip_address: '52.9.112.5', public: true, status: 'Running', criticality: 'Low'})
        """,
        
        # 6. Create DataStore nodes
        """
        CREATE (dcustomer:DataStore:Asset {id: 'd-customer-db', name: 'prod-customer-aurora-db', type: 'DataStore', db_type: 'RDS PostgreSQL', criticality: 'High'})
        CREATE (dfinance:DataStore:Asset {id: 'd-financial-records', name: 'corp-financials-s3-bucket', type: 'DataStore', db_type: 'S3 Bucket', criticality: 'High'})
        CREATE (dassets:DataStore:Asset {id: 'd-app-assets', name: 'public-static-assets-s3', type: 'DataStore', db_type: 'S3 Bucket', criticality: 'Low'})
        CREATE (dlogs:DataStore:Asset {id: 'd-cloudtrail-logs', name: 'aws-cloudtrail-audit-logs', type: 'DataStore', db_type: 'S3 Bucket', criticality: 'High'})
        """,
        
        # 7. Create Vulnerability nodes
        """
        CREATE (v1:Vulnerability {id: 'v-cve-2024-1234', name: 'Remote Code Execution in Apache Struts', cve: 'CVE-2024-1234', severity: 'Critical', score: 9.8, description: 'Allows an unauthenticated remote attacker to execute arbitrary code on the target server.'})
        CREATE (v2:Vulnerability {id: 'v-cve-2023-38646', name: 'Metabase SSRF & RCE', cve: 'CVE-2023-38646', severity: 'High', score: 8.1, description: 'SSRF and pre-auth remote code execution in Metabase server allowing database credential leak.'})
        CREATE (v3:Vulnerability {id: 'v-cve-2024-9999', name: 'WordPress Plaintext Logins Leak', cve: 'CVE-2024-9999', severity: 'Medium', score: 5.3, description: 'Information disclosure vulnerability leaking login attempts and credentials in debug logs.'})
        """,
        
        # 8. Create relationships - MEMBER_OF (User -> Group)
        """
        MATCH (alice:User {id: 'u-alice'}), (bob:User {id: 'u-bob'}), (charlie:User {id: 'u-charlie'}), (david:User {id: 'u-david'}), (eve:User {id: 'u-eve'})
        MATCH (gdevs:Group {id: 'g-devs'}), (gsec:Group {id: 'g-security'}), (gmkt:Group {id: 'g-marketing'})
        CREATE (alice)-[:MEMBER_OF]->(gdevs)
        CREATE (bob)-[:MEMBER_OF]->(gdevs)
        CREATE (charlie)-[:MEMBER_OF]->(gsec)
        CREATE (david)-[:MEMBER_OF]->(gmkt)
        CREATE (eve)-[:MEMBER_OF]->(gdevs)
        """,
        
        # 9. Create relationships - ASSUMES (User/Group/Compute -> Role)
        """
        MATCH (alice:User {id: 'u-alice'}), (charlie:User {id: 'u-charlie'})
        MATCH (gdevs:Group {id: 'g-devs'}), (gsec:Group {id: 'g-security'})
        MATCH (radmin:Role {id: 'r-admin-role'}), (rdb:Role {id: 'r-db-reader'}), (rsec:Role {id: 'r-security-auditor'})
        CREATE (alice)-[:ASSUMES {reason: 'Emergency Break-Glass'}]->(radmin)
        CREATE (charlie)-[:ASSUMES {reason: 'IAM Auditor Provision'}]->(rsec)
        CREATE (gsec)-[:ASSUMES {reason: 'Security Ops'}]->(radmin)
        CREATE (gdevs)-[:ASSUMES {reason: 'Default DevOps Profile'}]->(rdb)
        """,
        
        # 10. Create relationships - RUNS_AS (Compute -> Role)
        """
        MATCH (cprodweb:Compute {id: 'c-prod-web'}), (cinternalapi:Compute {id: 'c-internal-api'})
        MATCH (rweb:Role {id: 'r-web-app'}), (rdb:Role {id: 'r-db-reader'})
        CREATE (cprodweb)-[:RUNS_AS]->(rweb)
        CREATE (cinternalapi)-[:RUNS_AS]->(rdb)
        """,
        
        # 11. Create relationships - HAS_ACCESS (Role/Group -> DataStore/Compute)
        """
        MATCH (radmin:Role {id: 'r-admin-role'}), (rdb:Role {id: 'r-db-reader'}), (rweb:Role {id: 'r-web-app'}), (rsec:Role {id: 'r-security-auditor'}), (gmkt:Group {id: 'g-marketing'})
        MATCH (dcustomer:DataStore {id: 'd-customer-db'}), (dfinance:DataStore {id: 'd-financial-records'}), (dassets:DataStore {id: 'd-app-assets'}), (dlogs:DataStore {id: 'd-cloudtrail-logs'})
        MATCH (cinternalapi:Compute {id: 'c-internal-api'}), (cprodweb:Compute {id: 'c-prod-web'})
        CREATE (radmin)-[:HAS_ACCESS {privilege: 'Admin', permission: '*:*'}]->(dcustomer)
        CREATE (radmin)-[:HAS_ACCESS {privilege: 'Admin', permission: '*:*'}]->(dfinance)
        CREATE (radmin)-[:HAS_ACCESS {privilege: 'Admin', permission: '*:*'}]->(dlogs)
        CREATE (radmin)-[:HAS_ACCESS {privilege: 'Admin', permission: '*:*'}]->(cinternalapi)
        CREATE (rdb)-[:HAS_ACCESS {privilege: 'Read', permission: 'rds:DescribeDBInstances'}]->(dcustomer)
        CREATE (rweb)-[:HAS_ACCESS {privilege: 'Read', permission: 's3:GetObject'}]->(dassets)
        CREATE (rsec)-[:HAS_ACCESS {privilege: 'Read', permission: 's3:GetObject'}]->(dlogs)
        CREATE (gmkt)-[:HAS_ACCESS {privilege: 'Write', permission: 's3:PutObject'}]->(dassets)
        """,
        
        # 12. Create relationships - ACCESSIBLE_FROM (Compute -> Compute)
        """
        MATCH (cdevbastion:Compute {id: 'c-dev-bastion'}), (cinternalapi:Compute {id: 'c-internal-api'}), (cprodweb:Compute {id: 'c-prod-web'})
        CREATE (cinternalapi)-[:ACCESSIBLE_FROM {port: 22, protocol: 'SSH'}]->(cdevbastion)
        CREATE (cprodweb)-[:ACCESSIBLE_FROM {port: 22, protocol: 'SSH'}]->(cdevbastion)
        """,
        
        # 13. Create relationships - VULNERABLE_TO (Compute -> Vulnerability)
        """
        MATCH (cprodweb:Compute {id: 'c-prod-web'}), (cdevbastion:Compute {id: 'c-dev-bastion'}), (cmktsite:Compute {id: 'c-marketing-site'})
        MATCH (v1:Vulnerability {id: 'v-cve-2024-1234'}), (v2:Vulnerability {id: 'v-cve-2023-38646'}), (v3:Vulnerability {id: 'v-cve-2024-9999'})
        CREATE (cprodweb)-[:VULNERABLE_TO]->(v1)
        CREATE (cdevbastion)-[:VULNERABLE_TO]->(v2)
        CREATE (cmktsite)-[:VULNERABLE_TO]->(v3)
        """,
        
        # 14. Create relationships - EXPLOIT_LEADS_TO (Vulnerability -> Role/Identity)
        """
        MATCH (v1:Vulnerability {id: 'v-cve-2024-1234'}), (v2:Vulnerability {id: 'v-cve-2023-38646'})
        MATCH (radmin:Role {id: 'r-admin-role'}), (rdb:Role {id: 'r-db-reader'})
        CREATE (v1)-[:EXPLOIT_LEADS_TO {impact: 'IAM Credentials Steal'}]->(radmin)
        CREATE (v2)-[:EXPLOIT_LEADS_TO {impact: 'IAM Instance Role Assume'}]->(rdb)
        """
    ]

    with driver.session() as session:
        for idx, query in enumerate(queries):
            print(f"Running query step {idx+1}/{len(queries)}...")
            session.run(query)

    print("Data loading completed successfully!")
    
    # Print database stats
    def print_stats(tx):
        node_res = tx.run("MATCH (n) RETURN labels(n) AS label, count(n) AS cnt")
        print("\nNodes Created:")
        for r in node_res:
            print(f"  {list(r['label'])}: {r['cnt']}")
            
        rel_res = tx.run("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS cnt")
        print("\nRelationships Created:")
        for r in rel_res:
            print(f"  {r['type']}: {r['cnt']}")

    with driver.session() as session:
        session.execute_read(print_stats)

    driver.close()
    print("\nDatabase seeded successfully!")

if __name__ == "__main__":
    seed_database()
