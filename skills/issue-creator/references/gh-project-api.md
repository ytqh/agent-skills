# GitHub Projects V2 API via `gh api graphql`

## Discover Projects Linked to a Repo

```bash
gh api graphql -f query='
  query($owner: String!, $repo: String!) {
    repository(owner: $owner, name: $repo) {
      projectsV2(first: 10) {
        nodes { id number title }
      }
    }
  }
' -f owner=OWNER -f repo=REPO
```

## Get Project Fields (Status, Priority, etc.)

```bash
gh api graphql -f query='
  query($projectId: ID!) {
    node(id: $projectId) {
      ... on ProjectV2 {
        fields(first: 20) {
          nodes {
            ... on ProjectV2SingleSelectField {
              id name options { id name }
            }
            ... on ProjectV2Field {
              id name
            }
            ... on ProjectV2IterationField {
              id name
            }
          }
        }
      }
    }
  }
' -f projectId=PROJECT_NODE_ID
```

## Add Issue to Project

```bash
gh api graphql -f query='
  mutation($projectId: ID!, $contentId: ID!) {
    addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) {
      item { id }
    }
  }
' -f projectId=PROJECT_NODE_ID -f contentId=ISSUE_NODE_ID
```

## Get Issue Node ID

```bash
gh api graphql -f query='
  query($owner: String!, $repo: String!, $number: Int!) {
    repository(owner: $owner, name: $repo) {
      issue(number: $number) { id }
    }
  }
' -f owner=OWNER -f repo=REPO -F number=ISSUE_NUMBER
```

## Set Single-Select Field (Status / Priority)

```bash
gh api graphql -f query='
  mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
    updateProjectV2ItemFieldValue(input: {
      projectId: $projectId
      itemId: $itemId
      fieldId: $fieldId
      value: { singleSelectOptionId: $optionId }
    }) {
      projectV2Item { id }
    }
  }
' -f projectId=PROJECT_NODE_ID -f itemId=ITEM_ID -f fieldId=FIELD_ID -f optionId=OPTION_ID
```

## Typical Flow

1. Discover projects linked to repo
2. Get project fields to find Status/Priority field IDs and option IDs
3. Create issue with `gh issue create`
4. Get issue node ID
5. Add issue to project (`addProjectV2ItemById`)
6. Set Status and Priority fields (`updateProjectV2ItemFieldValue`)
