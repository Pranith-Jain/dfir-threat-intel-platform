# ADR 0026: AWS deployment inventory uses service-specific identity contracts

## Status

Accepted and live-provider verified on 2026-08-31. Automated connector, API, PostgreSQL,
production-web, exact account/Region validation, and eight-plane collection verification
pass. See the [live acceptance record](../product/aws-code-to-cloud-live-acceptance-2026-08-31.md).

## Decision

The `aws.code_to_cloud` connection scope validates and collects four independent regional
planes: Lambda functions, ECS task-definition families, EKS clusters, and SageMaker
endpoints. Each plane has separate inventory and relationship coverage, so a service failure
cannot become an empty result or withdraw observations from another service.

Collection uses the existing external-ID assume-role connection, rebinds the observed STS
account to the configured 12-digit account, and scans either every enabled Region or the
connection's exact selected-Region boundary. Pagination is limited to 100 pages and 10,000
resources per service and Region. Per-resource read failures make only that service plane
partial.

Every valid resource is retained as an observed `cloud_resource`. Lambda functions and ECS
task families become `ai_workload` assets only when they expose the explicit
`denali_ai_workload=true` tag or an allow-listed model/endpoint environment-variable name.
EKS clusters require the explicit tag because cluster existence alone does not prove an AI
workload. SageMaker endpoints are intrinsically model-serving resources and are eligible by
type. Arbitrary environment values, tag values, credentials, code, prompts, and responses are
never retained. The only environment values retained are syntactically bounded model identifiers
from allow-listed `*_MODEL_ID` keys when the key or identifier attributes the model to Bedrock.

Eligible workloads emit `HOSTED_ON` relationships to their cloud resource and `RUNS_AS`
relationships when Lambda role, ECS task role, EKS cluster role, or SageMaker model execution
role evidence is independently observed. A retained Bedrock identifier emits an observed `USES`
relationship from the workload to that exact model. Denali then reads only the linked execution
role's inline and attached IAM policies. A wildcard Bedrock invocation resource produces the
`DENALI-AWS-AI-IAM-001` finding; a denied or malformed IAM read makes this independent posture
plane partial and cannot become an empty result.

## Exact runtime identity contracts

### Optional exact Zip Lambda read plan

The native AWS connection accepts `coverage_mode: "selected-resource"` with a typed
`selected_resource` containing `kind: "lambda_zip"`, one unqualified `function_arn`,
one `execution_role_arn`, and an approved `expected_model_id` (bounded Bedrock ID or ARN).
This addition is implemented with local automated tests; production activation and real
resource/model acceptance remain a separate reviewed release gate. Existing connections
that omit this field retain the discovery behavior above; shared Platform AWS connections
are not changed by this native adapter.

The only declared scope is `aws.code_to_cloud`. Account and partition must match both
ARNs; `regions` must contain exactly the Lambda ARN Region, equal to `deployment_region`.
The generated reader has a different role name from the execution role, an external-ID
trust, and only these exact-resource permissions:

| Resource                 | Reads                                                                       |
| ------------------------ | --------------------------------------------------------------------------- |
| Exact Lambda ARN         | `lambda:GetFunctionConfiguration`, `lambda:ListTags`                        |
| Exact execution-role ARN | `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies`, `iam:GetRolePolicy` |

The server-resolved tenant reloads the stored plan before collection. STS account,
partition and assumed-reader identity must match. Returned function ARN/name, Zip
packaging, execution role, and allow-listed model-ID metadata must match every pin.
Missing or ambiguous model metadata fails the resource proof. No function list,
enabled-Region discovery, ECS/EKS/SageMaker reads, code download, logs or invocation occur.
Configuration responses can contain other environment values in memory; only the pinned
model-ID metadata and bounded deployment metadata are retained, never arbitrary values.

Collection reuses the observed deployment/model/role assertions and relationships, then
Denali's existing `DENALI-AWS-AI-IAM-001` evaluator on this execution role. IAM pagination,
returned role/policy names, and supported policy-document shape require explicit proof.
Nonempty/incomplete attached-policy inventory or unsupported inline policy grammar makes
the IAM plane partial; it never expands into `GetPolicy` or `GetPolicyVersion` reads.
This check is an observed inline-policy posture signal, not an effective-permissions or
account-wide security certification.

Successful reads report `resource_coverage_state: "complete"` separately from the overall
`state: "partial"` and `account_coverage: "not_assessed"`. The connection remains partial
even when both exact read planes pass. Durable validation/collection jobs and normal
result reads are reused; collection is explicitly requested, not automatically triggered
by account-wide healthy status. Setup/status projections expose only the four public
selection fields. UI/API/MCP use the same product create/validate/collect operations;
the Platform gateway must deploy its matching typed optional create field before claiming
MCP creation parity. No provider grants, deployment, model invocation or remediation are
performed by these tests or by creating a Denali plan.

For a live QA plan, approve the real function, separate read role, execution role and model
before resource setup. Do not replace an existing discovery stack, reuse an execution role
as the reader, widen healthy connectors, or infer that an existing broad role became narrow
solely from this plan's template. Review the actual IAM grants at setup acceptance.

All new direct-inventory joins require exact account ID and Region plus one service-specific
identifier:

| Service             | Runtime kind          | Exact identifier |
| ------------------- | --------------------- | ---------------- |
| Lambda              | `serverless_function` | `function_name`  |
| ECS task definition | `container_task`      | `task_family`    |
| EKS cluster         | `kubernetes_cluster`  | `cluster_name`   |
| SageMaker endpoint  | `model_endpoint`      | `endpoint_name`  |

The accepted CDK/CloudFormation Lambda and ECS join remains unchanged: it still requires the
observed CloudFormation logical-ID prefix plus exact function or container name. Direct
account inventory is an additional identity contract, not a relaxation of that contract.

## Source declaration contracts

Terraform supports `aws_lambda_function`, `aws_ecs_task_definition`, `aws_eks_cluster`, and
`aws_sagemaker_endpoint`. The default AWS provider must contain a literal `region` and exactly
one literal 12-digit `allowed_account_ids` value. Each resource must also contain its literal
service name field (`function_name`, `family`, or `name`).

SAM and CloudFormation YAML/JSON support `AWS::Serverless::Function`,
`AWS::Lambda::Function`, `AWS::ECS::TaskDefinition`, `AWS::EKS::Cluster`, and
`AWS::SageMaker::Endpoint`. Templates must declare literal boundary metadata:

```yaml
Metadata:
  Denali:
    AccountId: '123456789012'
    Region: us-east-1
```

The resource's corresponding name property must also be literal. Dynamic or incomplete
values produce a visible analysis warning and no deployment relationship.

## Consequences

- Existing AWS connections created without `aws.code_to_cloud` cannot collect this inventory;
  the UI explains that a new scoped plan is required.
- EKS correlation in this step proves only repository-to-cluster intent. The shared
  Kubernetes workload contract is defined separately in
  [ADR 0027](0027-shared-kubernetes-code-to-cloud.md).
- Artifact identity and source-revision attestation remain separate from an exact deployment
  identity match.
- A successful empty plane proves only that the bounded list operation completed.
