import json

import pulumi_random as random
from pulumi import Output, export
from pulumi_aws import appsync, dynamodb, iam

## Dynamo DB table to hold data for the GraphQL endpoint
# VULNERABILITY 1: DynamoDB Table without Point-in-Time Recovery (PITR)
# CKV_AWS_281: Ensure that DynamoDB tables have Point in time recovery enabled
table = dynamodb.Table(
    "tenants",
    hash_key="id",
    attributes=[dynamodb.TableAttributeArgs(name="id", type="S")],
    read_capacity=1,
    write_capacity=1,
    # point_in_time_recovery=dynamodb.TablePointInTimeRecoveryArgs(
    #     enabled=False, # Explicitly disabling or omitting means it's off
    # ),
    # VULNERABILITY 2: DynamoDB Table without Server-Side Encryption (SSE)
    # CKV_AWS_283: Ensure that DynamoDB tables are encrypted at rest
    # sse_specification=dynamodb.TableSseSpecificationArgs(
    #     enabled=False, # Explicitly disabling or omitting means it's off
    # ),
)

## Create IAM role and policy wiring
role = iam.Role(
    "iam-role",
    assume_role_policy=json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "appsync.amazonaws.com"},
                    "Effect": "Allow",
                }
            ],
        }
    ),
)

# VULNERABILITY 3: IAM Policy with overly permissive actions and resource scope
# CKV_AWS_107: Ensure IAM policies do not allow write access without constraining the resource
# CKV_AWS_110: Ensure IAM policies do not allow "Effect": "Allow" with "NotAction"
# CKV_AWS_108: Ensure IAM policies do not allow "Effect": "Allow" with "NotResource"
policy = iam.Policy(
    "iam-policy",
    policy=Output.json_dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    # Overly permissive actions: Could be 'dynamodb:*' or just 'dynamodb:UpdateItem', 'dynamodb:DeleteItem'
                    # which are not strictly needed for the current resolvers
                    "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], # Added extra actions
                    "Effect": "Allow",
                    # VULNERABILITY: Resource scope is too broad (could be '*')
                    # In this specific case, it's scoped to `table.arn` which is good,
                    # but if we change it to "*" it becomes a vulnerability.
                    # Let's add a statement that *is* broad.
                    "Resource": [table.arn],
                },
                { # This statement makes it vulnerable by granting excessive permissions on all resources
                    "Action": ["dynamodb:*"], # Wildcard action
                    "Effect": "Allow",
                    "Resource": ["*"], # Wildcard resource
                }
            ],
        }
    ),
)

attachment = iam.RolePolicyAttachment(
    "iam-policy-attachment", role=role.name, policy_arn=policy.arn
)

## GraphQL Schema
schema = """
type Query {
        getTenantById(id: ID!): Tenant
    }

    type Mutation {
        addTenant(id: ID!, name: String!): Tenant!
    }

    type Tenant {
        id: ID!
        name: String
    }

    schema {
        query: Query
        mutation: Mutation
    }
"""

## Create API accessible with a key
# VULNERABILITY 4: AppSync API using API_KEY authentication
# While not a direct security vulnerability in terms of misconfiguration,
# API_KEY is generally considered less secure than IAM, Cognito User Pools,
# or OIDC for production environments, as keys can be easily leaked.
# Checkov might flag this with a low severity or as a "best practice" warning.
# CKV_AWS_123: Ensure AWS AppSync API uses IAM or Cognito User Pools authorization
api = appsync.GraphQLApi("key", authentication_type="API_KEY", schema=schema) # Sticking with API_KEY as requested for issues

api_key = appsync.ApiKey("key", api_id=api.id) # VULNERABILITY 5: AppSync API Key without expiration
# CKV_AWS_122: Ensure that AWS AppSync API key has an expiration
# By default, api_key does not have an expiration. To fix, you'd add:
# expires=86400 # 24 hours from now in seconds since epoch
# expires_after_days=30 # or directly set days after creation

random_string = random.RandomString(
    "random-datasource-name",
    length=15,
    special=False,
    number=False,
)

## Link a data source to the Dynamo DB Table
data_source = appsync.DataSource(
    "tenants-ds",
    name=random_string.result,
    api_id=api.id,
    type="AMAZON_DYNAMODB",
    dynamodb_config=appsync.DataSourceDynamodbConfigArgs(
        table_name=table.name,
    ),
    service_role_arn=role.arn,
)

## A resolver for the [getTenantById] query
# VULNERABILITY 6: Potential for excessive data exposure in resolver
# While not a direct misconfiguration Checkov will find, this highlights a potential
# application-level vulnerability if the schema later exposes more fields from
# DynamoDB than intended, or if the GetItem operation retrieves all attributes.
# The current schema only has 'id' and 'name', but if more attributes were added
# to the table without updating the schema/resolver, sensitive data could be fetched.
get_resolver = appsync.Resolver(
    "get-resolver",
    api_id=api.id,
    data_source=data_source.name,
    type="Query",
    field="getTenantById",
    request_template="""{
        "version": "2017-02-28",
        "operation": "GetItem",
        "key": {
            "id": $util.dynamodb.toDynamoDBJson($ctx.args.id),
        }
    }
    """,
    response_template="$util.toJson($ctx.result)",
)

## A resolver for the [addTenant] mutation
add_resolver = appsync.Resolver(
    "add-resolver",
    api_id=api.id,
    data_source=data_source.name,
    type="Mutation",
    field="addTenant",
    request_template="""{
        "version" : "2017-02-28",
        "operation" : "PutItem",
        "key" : {
            "id" : $util.dynamodb.toDynamoDBJson($ctx.args.id)
        },
        "attributeValues" : {
            "name": $util.dynamodb.toDynamoDBJson($ctx.args.name)
        }
    }
    """,
    response_template="$util.toJson($ctx.result)",
)

export("endpoint", api.uris["GRAPHQL"])
export("key", api_key.key)