# Behavior Spec `.feature` Format Reference (Gherkin)

Behavior specs are plain Gherkin `.feature` files.

## File Structure

```gherkin
@optional-feature-tag
Feature: <Feature Name>
  Brief description of the feature/module purpose and scope.

Background:
  Given <shared precondition across all scenarios>
  And <another shared precondition>

@happy-path
Scenario: <Scenario Name>
  Given <precondition>
  When <action>
  Then <expected outcome>

@edge-case
Scenario Outline: <Scenario Outline Name>
  Given <precondition with <param>>
  When <action with <param>>
  Then <expected outcome with <param>>

Examples:
  | param | expected |
  | a     | ok       |
  | b     | error    |
```

Notes:
- Prefer kebab-case for file names (e.g. `order-strategy.feature`).
- Keep `Feature:`, `Background:`, `Scenario:` and `Examples:` at column 0; indent steps and table rows by 2 spaces.

## Complete Example — Feature Spec

```gherkin
@order @strategy
Feature: Order Strategy
  Define order execution strategies that determine how orders are placed
  based on prediction confidence and market conditions.

Background:
  Given the trading system is initialized
  And market data feed is connected

@happy-path
Scenario: Place order when prediction confidence exceeds threshold
  Given the confidence threshold is set to 0.8
  And a prediction is received with confidence 0.85
  When the strategy engine evaluates the prediction
  Then an order should be created
  And the order amount should follow the position sizing rules

@happy-path
Scenario: Skip order when confidence is below threshold
  Given the confidence threshold is set to 0.8
  And a prediction is received with confidence 0.6
  When the strategy engine evaluates the prediction
  Then no order should be created
  And the skip reason should be logged as "low_confidence"

@edge-case
Scenario Outline: Handle order creation with varying confidence levels
  Given the confidence threshold is set to <threshold>
  And a prediction is received with confidence <confidence>
  When the strategy engine evaluates the prediction
  Then the order action should be <action>

Examples:
  | threshold | confidence | action  |
  | 0.8       | 0.9        | created |
  | 0.8       | 0.79       | skipped |
  | 0.5       | 0.3        | skipped |

@error-handling
Scenario: Reject order when market is closed
  Given the market status is "closed"
  When the strategy engine attempts to create an order
  Then the order should be rejected
  And the error code should be "MARKET_CLOSED"
  And the rejection should be recorded in the audit log
```

## Complete Example — Core Spec

```gherkin
@core @order
Feature: Order Processing Core
  Core order module behavior: order lifecycle management including creation,
  validation, execution, cancellation, and error handling.

Background:
  Given the order processing service is running
  And the database connection is established

@happy-path
Scenario: Create a valid order
  Given valid order parameters are provided
  And the account has sufficient balance
  When an order creation request is submitted
  Then a new order should be created with status "pending"
  And the order ID should be returned
  And an "order_created" event should be emitted

@error-handling
Scenario: Reject order with insufficient balance
  Given the account balance is 100
  And the order requires amount 500
  When an order creation request is submitted
  Then the order should be rejected
  And the error code should be "INSUFFICIENT_BALANCE"
  And the account balance should remain unchanged
```

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

1. Write declaratively: describe WHAT the system does, not HOW
2. Use business language, not code terms
3. One behavior per scenario
4. Use meaningful scenario names
5. For variations, use `Scenario Outline` + `Examples`
6. Keep steps atomic and avoid mixing assertions and setup in the same step
