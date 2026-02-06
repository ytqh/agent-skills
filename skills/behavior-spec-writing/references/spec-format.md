# Behavior Spec YAML Format Reference

## File Structure

```yaml
feature: <Feature Name>
description: >
  Brief description of the feature or module's purpose and scope.

# Optional: link to plan or requirement docs
references:
  - docs/plan/<related-plan>.md

tags:
  - <global-tag>

background:
  given:
    - <shared precondition across all scenarios>

scenarios:
  - name: <Scenario Name>
    tags:
      - @happy-path
    steps:
      - given: <precondition>
      - when: <action>
      - then: <expected outcome>

  - name: <Scenario Outline Name>
    tags:
      - @edge-case
    outline: true
    steps:
      - given: <precondition with <param>>
      - when: <action with <param>>
      - then: <expected outcome with <param>>
    examples:
      - columns: [param1, param2, expected]
        rows:
          - [value1a, value2a, result_a]
          - [value1b, value2b, result_b]
```

## Complete Example — Feature Spec

```yaml
feature: Order Strategy
description: >
  Define order execution strategies that determine how orders are placed
  based on prediction confidence and market conditions.

references:
  - docs/plan/order-strategy-v2.md

tags:
  - order
  - strategy

background:
  given:
    - the trading system is initialized
    - market data feed is connected

scenarios:
  - name: Place order when prediction confidence exceeds threshold
    tags:
      - @happy-path
    steps:
      - given: the confidence threshold is set to 0.8
      - and: a prediction is received with confidence 0.85
      - when: the strategy engine evaluates the prediction
      - then: an order should be created
      - and: the order amount should follow the position sizing rules

  - name: Skip order when confidence is below threshold
    tags:
      - @happy-path
    steps:
      - given: the confidence threshold is set to 0.8
      - and: a prediction is received with confidence 0.6
      - when: the strategy engine evaluates the prediction
      - then: no order should be created
      - and: the skip reason should be logged as "low_confidence"

  - name: Handle order creation with varying confidence levels
    tags:
      - @edge-case
    outline: true
    steps:
      - given: the confidence threshold is set to <threshold>
      - and: a prediction is received with confidence <confidence>
      - when: the strategy engine evaluates the prediction
      - then: the order action should be <action>
    examples:
      - columns: [threshold, confidence, action]
        rows:
          - [0.8, 0.9, created]
          - [0.8, 0.8, created]
          - [0.8, 0.79, skipped]
          - [0.5, 0.5, created]
          - [0.5, 0.3, skipped]

  - name: Reject order when market is closed
    tags:
      - @error-handling
    steps:
      - given: the market status is "closed"
      - when: the strategy engine attempts to create an order
      - then: the order should be rejected
      - and: the error code should be "MARKET_CLOSED"
      - and: the rejection should be recorded in the audit log

  - name: Handle prediction service timeout
    tags:
      - @error-handling
    steps:
      - given: the prediction service response timeout is 5 seconds
      - when: the prediction service does not respond within 5 seconds
      - then: the pending evaluation should be cancelled
      - and: an alert should be sent with type "prediction_timeout"
      - and: the system should retry on the next evaluation cycle
```

## Complete Example — Core Spec

```yaml
feature: Order Processing Core
description: >
  Core order module behavior: order lifecycle management including
  creation, validation, execution, cancellation, and error handling.

tags:
  - core
  - order

background:
  given:
    - the order processing service is running
    - the database connection is established

scenarios:
  - name: Create a valid order
    tags:
      - @happy-path
    steps:
      - given: valid order parameters are provided
      - and: the account has sufficient balance
      - when: an order creation request is submitted
      - then: a new order should be created with status "pending"
      - and: the order ID should be returned
      - and: an "order_created" event should be emitted

  - name: Reject order with insufficient balance
    tags:
      - @error-handling
    steps:
      - given: the account balance is 100
      - and: the order requires amount 500
      - when: an order creation request is submitted
      - then: the order should be rejected
      - and: the error code should be "INSUFFICIENT_BALANCE"
      - and: the account balance should remain unchanged

  - name: Cancel a pending order
    tags:
      - @happy-path
    steps:
      - given: an order exists with status "pending"
      - when: a cancellation request is submitted for the order
      - then: the order status should change to "cancelled"
      - and: an "order_cancelled" event should be emitted
      - and: any reserved balance should be released

  - name: Prevent cancellation of executed order
    tags:
      - @error-handling
    steps:
      - given: an order exists with status "executed"
      - when: a cancellation request is submitted for the order
      - then: the cancellation should be rejected
      - and: the error code should be "ORDER_ALREADY_EXECUTED"
      - and: the order status should remain "executed"
```

## Gherkin Keywords in YAML

Map standard Gherkin keywords to YAML step keys:

| Gherkin Keyword | YAML Key | Purpose |
|----------------|----------|---------|
| Given | `given` | Setup precondition |
| When | `when` | Action / trigger |
| Then | `then` | Expected outcome / assertion |
| And | `and` | Continue previous step type |
| But | `but` | Negative continuation |

## Tagging Convention

| Tag | Meaning |
|-----|---------|
| `@happy-path` | Normal/expected flow |
| `@edge-case` | Boundary conditions, unusual inputs |
| `@error-handling` | Error scenarios, failure recovery |
| `@regression` | Previously broken, must not regress |
| `@pending` | Spec written, implementation not yet done |
| `@deprecated` | Behavior being phased out |

## Writing Guidelines

1. **Declarative, not imperative**: Write "the order should be created" not "click the submit button and check the database"
2. **Business language**: Use domain terms, not code terms. "order" not "OrderEntity", "balance" not "account_balance_field"
3. **One behavior per scenario**: Each scenario tests one specific behavior
4. **Meaningful names**: Scenario names should describe the behavior being specified
5. **Cover the error path**: For every happy path, consider what errors can occur
6. **Use Scenario Outline for variations**: When testing same behavior with different inputs, use outline + examples table
7. **Keep steps atomic**: Each step should describe one thing
